package configmap

import (
	"reflect"
	"testing"

	"time"

	core_v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/kubernetes/typed/core/v1/fake"
	k8stesting "k8s.io/client-go/testing"
	"sigs.k8s.io/aws-iam-authenticator/pkg/config"
)

var testUser = config.UserMapping{Username: "matlan", Groups: []string{"system:master", "dev"}}
var testRole = config.RoleMapping{Username: "computer", Groups: []string{"system:nodes"}}

func makeStore() MapStore {
	ms := MapStore{
		users:       make(map[string]config.UserMapping),
		roles:       make(map[string]config.RoleMapping),
		awsAccounts: make(map[string]interface{}),
	}
	ms.users["matt"] = testUser
	ms.roles["instance"] = testRole
	ms.awsAccounts["123"] = nil
	return ms
}

func makeStoreWClient() (MapStore, *fake.FakeConfigMaps) {
	fakeConfigMaps := &fake.FakeConfigMaps{}
	fakeConfigMaps.Fake = &fake.FakeCoreV1{}
	fakeConfigMaps.Fake.Fake = &k8stesting.Fake{}
	ms := MapStore{
		users:     make(map[string]config.UserMapping),
		roles:     make(map[string]config.RoleMapping),
		configMap: v1.ConfigMapInterface(fakeConfigMaps),
	}
	return ms, fakeConfigMaps
}

func TestUserMapping(t *testing.T) {
	ms := makeStore()
	user, err := ms.UserMapping("matt")
	if err != nil {
		t.Errorf("Could not find user 'matt' in map")
	}
	if !reflect.DeepEqual(user, testUser) {
		t.Errorf("User for 'matt' does not match expected values. (Actual: %+v, Expected: %+v", user, testUser)
	}

	user, err = ms.UserMapping("nic")
	if err != UserNotFound {
		t.Errorf("UserNotFound error was not returned for user 'nic'")
	}
	if !reflect.DeepEqual(user, config.UserMapping{}) {
		t.Errorf("User value returned when user is not in the map was not empty: %+v", user)
	}
}

func TestRoleMapping(t *testing.T) {
	ms := makeStore()
	role, err := ms.RoleMapping("instance")
	if err != nil {
		t.Errorf("Could not find user 'instance in map")
	}
	if !reflect.DeepEqual(role, testRole) {
		t.Errorf("Role for 'instance' does not match expected value. (Acutal: %+v, Expected: %+v", role, testRole)
	}

	role, err = ms.RoleMapping("borg")
	if err != RoleNotFound {
		t.Errorf("RoleNotFound error was not returend for role 'borg'")
	}
	if !reflect.DeepEqual(role, config.RoleMapping{}) {
		t.Errorf("Role value returend when role is not in map was not empty: %+v", role)
	}
}

func TestAWSAccount(t *testing.T) {
	ms := makeStore()
	if !ms.AWSAccount("123") {
		t.Errorf("Expected aws account '123' to be in accounts list: %v", ms.awsAccounts)
	}
	if ms.AWSAccount("345") {
		t.Errorf("Did not expect account '345' to be in accounts list: %v", ms.awsAccounts)
	}
}

var userMapping = `
-
  userarn: "arn:iam:matlan"
  username: matlan
  groups:
    - loadedfromconfigmap
    - "system:master"
-
  groups:
    - "system:master"
  userarn: "arn:iam:NIC"
  username: nic
`

var roleMapping = `
- rolearn: "arn:iam:123:role/me"
  username: "{{Session}}"
  groups:
    - system:nodes
`

var updatedUserMapping = `
-
  groups:
    - "system:master"
    - "test"
  userarn: "arn:iam:NIC"
  username: nic
- userarn: "arn:iam:beswar"
  username: beswar
  groups:
    - "system:master"
- userarn: "arn:iam:nogroups"
  username: nogroups
`

var updatedRoleMapping = `
- rolearn: "arn:iam:123:role/me"
  username: "{{Session}}"
  groups:
    - system:nodes
- rolearn: "arn:iam:123:role/you"
  username: "test"
  groups:
    - system:nodes
`

var autoMappedAWSAccountsYAML = `
- 123
- 345
`

var updatedAWSAccountsYAML = `
- 567
`

func TestLoadConfigMap(t *testing.T) {
	ms, fakeConfigMaps := makeStoreWClient()

	watcher := watch.NewFake()

	fakeConfigMaps.Fake.Fake.AddWatchReactor("configmaps",
		func(action k8stesting.Action) (handled bool, ret watch.Interface, err error) {
			return true, watcher, nil
		})

	ms.startLoadConfigMap()

	time.Sleep(2 * time.Millisecond)

	meta := metav1.ObjectMeta{Name: "aws-auth"}
	data := make(map[string]string)
	data["mapUsers"] = userMapping
	data["mapRoles"] = roleMapping
	data["mapAccounts"] = autoMappedAWSAccountsYAML

	watcher.Add(&core_v1.ConfigMap{ObjectMeta: meta, Data: data})

	time.Sleep(2 * time.Millisecond)

	if !ms.AWSAccount("123") {
		t.Errorf("AWS Account '123' not in allowed accounts")
	}

	if !ms.AWSAccount("345") {
		t.Errorf("AWS Account '345' not in allowed accounts")
	}

	expectedUser := config.UserMapping{
		UserARN:  "arn:iam:NIC",
		Username: "nic",
		Groups:   []string{"system:master"},
	}

	user, err := ms.UserMapping("arn:iam:nic")
	if err != nil {
		t.Errorf("Expected to find user 'nic' but got error: %v", err)
	}
	if !reflect.DeepEqual(user, expectedUser) {
		t.Errorf("User returned from mapping does not match expected user. (Actual: %+v, Expected: %+v", user, expectedUser)
	}

	updateData := make(map[string]string)
	updateData["mapUsers"] = updatedUserMapping
	updateData["mapRoles"] = updatedRoleMapping
	updateData["mapAccounts"] = updatedAWSAccountsYAML
	watcher.Modify(&core_v1.ConfigMap{ObjectMeta: meta, Data: updateData})

	//TODO: Sync without using sleep
	time.Sleep(10 * time.Millisecond)

	if ms.AWSAccount("345") {
		t.Errorf("AWS Account '345' is in map after update")
	}

	if !ms.AWSAccount("567") {
		t.Errorf("AWS Account '567' is not in map after update")
	}

	expectedUser.Groups = append(expectedUser.Groups, "test")
	user, err = ms.UserMapping("arn:iam:nic")
	if !reflect.DeepEqual(user, expectedUser) {
		t.Errorf("Updated returned from mapping does not match expected user. (Actual: %+v, Expected: %+v", user, expectedUser)
	}

	expectedUser = config.UserMapping{
		UserARN:  "arn:iam:beswar",
		Username: "beswar",
		Groups:   []string{"system:master"},
	}

	user, err = ms.UserMapping("arn:iam:beswar")
	if !reflect.DeepEqual(user, expectedUser) {
		t.Errorf("Updated did not return new user 'arn:iam:beswar', matching expected value. (Actual: %+v, Expected: %+v", user, expectedUser)
	}

	user, err = ms.UserMapping("arn:iam:matlan")
	if err != UserNotFound {
		t.Errorf("Expected updated mapping not to contain user 'arn:iam:matlan', got err: %v", err)
	}

}
