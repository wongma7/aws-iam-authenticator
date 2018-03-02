package configmap

import (
	"errors"
	"sync"

	"fmt"

	"strings"
	"time"

	"github.com/heptio/authenticator/pkg/config"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
	core_v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/clientcmd"
)

type MapStore struct {
	mutex sync.RWMutex
	users map[string]config.UserMapping
	roles map[string]config.RoleMapping
	// TODO: Use kubernetes set.
	// Used as set.
	awsAccounts map[string]interface{}
	configMap   v1.ConfigMapInterface
	initialized bool
}

func New(masterURL, kubeConfig string) (*MapStore, error) {
	clientconfig, err := clientcmd.BuildConfigFromFlags(masterURL, kubeConfig)
	if err != nil {
		return nil, err
	}
	clientset, err := kubernetes.NewForConfig(clientconfig)
	if err != nil {
		return nil, err
	}

	ms := MapStore{}
	// TODO: Should we use a namespace?  Make it configurable?
	ms.configMap = clientset.CoreV1().ConfigMaps(core_v1.NamespaceDefault)
	err = ms.loadConfigMapUnsafe()
	// TODO: Handle error
	if err != nil {
		logrus.Warnf("Could not load config map at startup.  Will try again on first request. error: %+v", err)
	}
	return &ms, nil
}

// Acquire lock before calling
func (ms *MapStore) loadConfigMapUnsafe() error {
	// TODO: convert to single config map instead of each group of values being its own map.
	cm, err := ms.configMap.Get("aws-auth", metav1.GetOptions{})
	if err != nil {
		logrus.Warnf("Could not get config map: %v", err)
		return err
	}

	ms.parseMap(cm.Data)

	watcher, err := ms.configMap.Watch(metav1.ListOptions{
		Watch: true,
	})

	if err != nil {
		logrus.Warnf("Could not start watch on config map: %v", err)
		return err
	}

	go func() {
		watcher := watcher
		var err error
		for {
			for r := range watcher.ResultChan() {
				switch r.Type {
				case watch.Error:
					logrus.WithFields(logrus.Fields{"error": r}).Error("recieved a watch error")
				case watch.Deleted:
					ms.mutex.Lock()
					logrus.Info("Resetting configmap on delete")
					ms.users = make(map[string]config.UserMapping)
					ms.roles = make(map[string]config.RoleMapping)
					ms.awsAccounts = make(map[string]interface{})
					ms.mutex.Unlock()
				case watch.Added:
					fallthrough
				case watch.Modified:
					// Type assertion is not working
					//
					// cm, ok := r.Object.(*core_v1.ConfigMap)
					//if !ok || cm.Name != "aws-auth" {
					//	break
					//}
					switch cm := r.Object.(type) {
					case *core_v1.ConfigMap:
						// TODO: Only watch on configmap/awsauth
						if cm.Name != "aws-auth" {
							break
						}
						logrus.Info("Received aws-auth watch event")
						ms.mutex.Lock()
						err := ms.parseMap(cm.Data)
						ms.mutex.Unlock()
						if err != nil {
							logrus.Error(err)
						}
					}

				}
			}
			logrus.Error("Watch channel closed.")
			watcher, err = ms.configMap.Watch(metav1.ListOptions{
				Watch: true,
			})
			if err != nil {
				logrus.Warn("Unable to re-establish watch.  Sleeping for 5 seconds")
				time.Sleep(5 * time.Second)
			}
		}
	}()

	ms.initialized = true

	return nil
}

type ErrParsingMap struct {
	errors []error
}

func (err ErrParsingMap) Error() string {
	return fmt.Sprintf("error parsing config map: %v", err.errors)
}

// Acquire lock before calling
func (ms *MapStore) parseMap(m map[string]string) error {
	// TODO: Look at errors.Wrap().
	errs := make([]error, 0)
	userMappings := make([]config.UserMapping, 0)
	if userData, ok := m["mapUsers"]; ok {
		err := yaml.Unmarshal([]byte(userData), &userMappings)
		if err != nil {
			errs = append(errs, err)
		}
	}

	roleMappings := make([]config.RoleMapping, 0)
	if roleData, ok := m["mapRoles"]; ok {
		err := yaml.Unmarshal([]byte(roleData), &roleMappings)
		if err != nil {
			errs = append(errs, err)
		}
	}

	awsAccounts := make([]string, 0)
	if accountsData, ok := m["autoMappedAWSAccounts"]; ok {
		err := yaml.Unmarshal([]byte(accountsData), &awsAccounts)
		if err != nil {
			errs = append(errs, err)
		}
	}

	// TODO: Check for empty user and role mappings.

	if len(errs) > 0 {
		logrus.Warnf("Errors parsing configmap: %+v", errs)
		return ErrParsingMap{errors: errs}
	}

	ms.users = make(map[string]config.UserMapping)
	ms.roles = make(map[string]config.RoleMapping)
	ms.awsAccounts = make(map[string]interface{})

	for _, user := range userMappings {
		ms.users[strings.ToLower(user.UserARN)] = user
	}
	for _, role := range roleMappings {
		ms.roles[strings.ToLower(role.RoleARN)] = role
	}
	for _, awsAccount := range awsAccounts {
		ms.awsAccounts[awsAccount] = nil
	}
	return nil
}

// UserNotFound is the error returned when the user is not found in the config map.
var UserNotFound = errors.New("User not found in configmap")

// RoleNotFound is the error returned when the role is not found in the config map.
var RoleNotFound = errors.New("Role not found in configmap")

func (ms *MapStore) UserMapping(arn string) (config.UserMapping, error) {
	ms.mutex.Lock()
	defer ms.mutex.Unlock()
	if !ms.initialized {
		err := ms.loadConfigMapUnsafe()
		if err != nil {
			// TODO: Log failed to load config map
			return config.UserMapping{}, UserNotFound
		}
	}
	if user, ok := ms.users[arn]; !ok {
		return config.UserMapping{}, UserNotFound
	} else {
		return user, nil
	}
}

func (ms *MapStore) RoleMapping(arn string) (config.RoleMapping, error) {
	ms.mutex.Lock()
	defer ms.mutex.Unlock()
	if !ms.initialized {
		err := ms.loadConfigMapUnsafe()
		if err != nil {
			// TODO: Log failed to load config map
			return config.RoleMapping{}, UserNotFound
		}
	}
	if role, ok := ms.roles[arn]; !ok {
		return config.RoleMapping{}, RoleNotFound
	} else {
		return role, nil
	}
}

func (ms *MapStore) AWSAccount(id string) bool {
	ms.mutex.RLock()
	defer ms.mutex.RUnlock()
	if !ms.initialized {
		err := ms.loadConfigMapUnsafe()
		if err != nil {
			// TODO: Log failed to load config map
			return false
		}
	}
	_, ok := ms.awsAccounts[id]
	return ok
}
