// Code generated by mockery v1.0.0. DO NOT EDIT.

package mocks

import (
	model "github.com/mattermost/mattermost-cloud/model"
	mock "github.com/stretchr/testify/mock"
)

// Store is an autogenerated mock type for the Store type
type Store struct {
	mock.Mock
}

// CreateCluster provides a mock function with given fields: cluster
func (_m *Store) CreateCluster(cluster *model.Cluster) error {
	ret := _m.Called(cluster)

	var r0 error
	if rf, ok := ret.Get(0).(func(*model.Cluster) error); ok {
		r0 = rf(cluster)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// CreateClusterInstallationMigration provides a mock function with given fields: migration
func (_m *Store) CreateClusterInstallationMigration(migration *model.ClusterInstallationMigration) error {
	ret := _m.Called(migration)

	var r0 error
	if rf, ok := ret.Get(0).(func(*model.ClusterInstallationMigration) error); ok {
		r0 = rf(migration)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// CreateGroup provides a mock function with given fields: group
func (_m *Store) CreateGroup(group *model.Group) error {
	ret := _m.Called(group)

	var r0 error
	if rf, ok := ret.Get(0).(func(*model.Group) error); ok {
		r0 = rf(group)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// CreateInstallation provides a mock function with given fields: installation
func (_m *Store) CreateInstallation(installation *model.Installation) error {
	ret := _m.Called(installation)

	var r0 error
	if rf, ok := ret.Get(0).(func(*model.Installation) error); ok {
		r0 = rf(installation)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// CreateWebhook provides a mock function with given fields: webhook
func (_m *Store) CreateWebhook(webhook *model.Webhook) error {
	ret := _m.Called(webhook)

	var r0 error
	if rf, ok := ret.Get(0).(func(*model.Webhook) error); ok {
		r0 = rf(webhook)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DeleteCluster provides a mock function with given fields: clusterID
func (_m *Store) DeleteCluster(clusterID string) error {
	ret := _m.Called(clusterID)

	var r0 error
	if rf, ok := ret.Get(0).(func(string) error); ok {
		r0 = rf(clusterID)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DeleteGroup provides a mock function with given fields: groupID
func (_m *Store) DeleteGroup(groupID string) error {
	ret := _m.Called(groupID)

	var r0 error
	if rf, ok := ret.Get(0).(func(string) error); ok {
		r0 = rf(groupID)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DeleteInstallation provides a mock function with given fields: installationID
func (_m *Store) DeleteInstallation(installationID string) error {
	ret := _m.Called(installationID)

	var r0 error
	if rf, ok := ret.Get(0).(func(string) error); ok {
		r0 = rf(installationID)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DeleteWebhook provides a mock function with given fields: webhookID
func (_m *Store) DeleteWebhook(webhookID string) error {
	ret := _m.Called(webhookID)

	var r0 error
	if rf, ok := ret.Get(0).(func(string) error); ok {
		r0 = rf(webhookID)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// GetCluster provides a mock function with given fields: clusterID
func (_m *Store) GetCluster(clusterID string) (*model.Cluster, error) {
	ret := _m.Called(clusterID)

	var r0 *model.Cluster
	if rf, ok := ret.Get(0).(func(string) *model.Cluster); ok {
		r0 = rf(clusterID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.Cluster)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(clusterID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetClusterInstallation provides a mock function with given fields: clusterInstallationID
func (_m *Store) GetClusterInstallation(clusterInstallationID string) (*model.ClusterInstallation, error) {
	ret := _m.Called(clusterInstallationID)

	var r0 *model.ClusterInstallation
	if rf, ok := ret.Get(0).(func(string) *model.ClusterInstallation); ok {
		r0 = rf(clusterInstallationID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.ClusterInstallation)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(clusterInstallationID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetClusterInstallationMigration provides a mock function with given fields: migrationID
func (_m *Store) GetClusterInstallationMigration(migrationID string) (*model.ClusterInstallationMigration, error) {
	ret := _m.Called(migrationID)

	var r0 *model.ClusterInstallationMigration
	if rf, ok := ret.Get(0).(func(string) *model.ClusterInstallationMigration); ok {
		r0 = rf(migrationID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.ClusterInstallationMigration)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(migrationID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetClusterInstallationMigrations provides a mock function with given fields: filter
func (_m *Store) GetClusterInstallationMigrations(filter *model.ClusterInstallationMigrationFilter) ([]*model.ClusterInstallationMigration, error) {
	ret := _m.Called(filter)

	var r0 []*model.ClusterInstallationMigration
	if rf, ok := ret.Get(0).(func(*model.ClusterInstallationMigrationFilter) []*model.ClusterInstallationMigration); ok {
		r0 = rf(filter)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*model.ClusterInstallationMigration)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*model.ClusterInstallationMigrationFilter) error); ok {
		r1 = rf(filter)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetClusterInstallations provides a mock function with given fields: filter
func (_m *Store) GetClusterInstallations(filter *model.ClusterInstallationFilter) ([]*model.ClusterInstallation, error) {
	ret := _m.Called(filter)

	var r0 []*model.ClusterInstallation
	if rf, ok := ret.Get(0).(func(*model.ClusterInstallationFilter) []*model.ClusterInstallation); ok {
		r0 = rf(filter)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*model.ClusterInstallation)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*model.ClusterInstallationFilter) error); ok {
		r1 = rf(filter)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetClusters provides a mock function with given fields: filter
func (_m *Store) GetClusters(filter *model.ClusterFilter) ([]*model.Cluster, error) {
	ret := _m.Called(filter)

	var r0 []*model.Cluster
	if rf, ok := ret.Get(0).(func(*model.ClusterFilter) []*model.Cluster); ok {
		r0 = rf(filter)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*model.Cluster)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*model.ClusterFilter) error); ok {
		r1 = rf(filter)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetGroup provides a mock function with given fields: groupID
func (_m *Store) GetGroup(groupID string) (*model.Group, error) {
	ret := _m.Called(groupID)

	var r0 *model.Group
	if rf, ok := ret.Get(0).(func(string) *model.Group); ok {
		r0 = rf(groupID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.Group)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(groupID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetGroups provides a mock function with given fields: filter
func (_m *Store) GetGroups(filter *model.GroupFilter) ([]*model.Group, error) {
	ret := _m.Called(filter)

	var r0 []*model.Group
	if rf, ok := ret.Get(0).(func(*model.GroupFilter) []*model.Group); ok {
		r0 = rf(filter)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*model.Group)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*model.GroupFilter) error); ok {
		r1 = rf(filter)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetInstallation provides a mock function with given fields: installationID
func (_m *Store) GetInstallation(installationID string) (*model.Installation, error) {
	ret := _m.Called(installationID)

	var r0 *model.Installation
	if rf, ok := ret.Get(0).(func(string) *model.Installation); ok {
		r0 = rf(installationID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.Installation)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(installationID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetInstallations provides a mock function with given fields: filter
func (_m *Store) GetInstallations(filter *model.InstallationFilter) ([]*model.Installation, error) {
	ret := _m.Called(filter)

	var r0 []*model.Installation
	if rf, ok := ret.Get(0).(func(*model.InstallationFilter) []*model.Installation); ok {
		r0 = rf(filter)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*model.Installation)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*model.InstallationFilter) error); ok {
		r1 = rf(filter)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetWebhook provides a mock function with given fields: webhookID
func (_m *Store) GetWebhook(webhookID string) (*model.Webhook, error) {
	ret := _m.Called(webhookID)

	var r0 *model.Webhook
	if rf, ok := ret.Get(0).(func(string) *model.Webhook); ok {
		r0 = rf(webhookID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.Webhook)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(webhookID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetWebhooks provides a mock function with given fields: filter
func (_m *Store) GetWebhooks(filter *model.WebhookFilter) ([]*model.Webhook, error) {
	ret := _m.Called(filter)

	var r0 []*model.Webhook
	if rf, ok := ret.Get(0).(func(*model.WebhookFilter) []*model.Webhook); ok {
		r0 = rf(filter)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*model.Webhook)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*model.WebhookFilter) error); ok {
		r1 = rf(filter)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// LockCluster provides a mock function with given fields: clusterID, lockerID
func (_m *Store) LockCluster(clusterID string, lockerID string) (bool, error) {
	ret := _m.Called(clusterID, lockerID)

	var r0 bool
	if rf, ok := ret.Get(0).(func(string, string) bool); ok {
		r0 = rf(clusterID, lockerID)
	} else {
		r0 = ret.Get(0).(bool)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string, string) error); ok {
		r1 = rf(clusterID, lockerID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// LockClusterInstallationMigration provides a mock function with given fields: migrationID, lockerID
func (_m *Store) LockClusterInstallationMigration(migrationID string, lockerID string) (bool, error) {
	ret := _m.Called(migrationID, lockerID)

	var r0 bool
	if rf, ok := ret.Get(0).(func(string, string) bool); ok {
		r0 = rf(migrationID, lockerID)
	} else {
		r0 = ret.Get(0).(bool)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string, string) error); ok {
		r1 = rf(migrationID, lockerID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// LockInstallation provides a mock function with given fields: installationID, lockerID
func (_m *Store) LockInstallation(installationID string, lockerID string) (bool, error) {
	ret := _m.Called(installationID, lockerID)

	var r0 bool
	if rf, ok := ret.Get(0).(func(string, string) bool); ok {
		r0 = rf(installationID, lockerID)
	} else {
		r0 = ret.Get(0).(bool)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string, string) error); ok {
		r1 = rf(installationID, lockerID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// UnlockCluster provides a mock function with given fields: clusterID, lockerID, force
func (_m *Store) UnlockCluster(clusterID string, lockerID string, force bool) (bool, error) {
	ret := _m.Called(clusterID, lockerID, force)

	var r0 bool
	if rf, ok := ret.Get(0).(func(string, string, bool) bool); ok {
		r0 = rf(clusterID, lockerID, force)
	} else {
		r0 = ret.Get(0).(bool)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string, string, bool) error); ok {
		r1 = rf(clusterID, lockerID, force)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// UnlockClusterInstallationMigration provides a mock function with given fields: migrationID, lockerID, force
func (_m *Store) UnlockClusterInstallationMigration(migrationID string, lockerID string, force bool) (bool, error) {
	ret := _m.Called(migrationID, lockerID, force)

	var r0 bool
	if rf, ok := ret.Get(0).(func(string, string, bool) bool); ok {
		r0 = rf(migrationID, lockerID, force)
	} else {
		r0 = ret.Get(0).(bool)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string, string, bool) error); ok {
		r1 = rf(migrationID, lockerID, force)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// UnlockInstallation provides a mock function with given fields: installationID, lockerID, force
func (_m *Store) UnlockInstallation(installationID string, lockerID string, force bool) (bool, error) {
	ret := _m.Called(installationID, lockerID, force)

	var r0 bool
	if rf, ok := ret.Get(0).(func(string, string, bool) bool); ok {
		r0 = rf(installationID, lockerID, force)
	} else {
		r0 = ret.Get(0).(bool)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string, string, bool) error); ok {
		r1 = rf(installationID, lockerID, force)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// UpdateCluster provides a mock function with given fields: cluster
func (_m *Store) UpdateCluster(cluster *model.Cluster) error {
	ret := _m.Called(cluster)

	var r0 error
	if rf, ok := ret.Get(0).(func(*model.Cluster) error); ok {
		r0 = rf(cluster)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// UpdateGroup provides a mock function with given fields: group
func (_m *Store) UpdateGroup(group *model.Group) error {
	ret := _m.Called(group)

	var r0 error
	if rf, ok := ret.Get(0).(func(*model.Group) error); ok {
		r0 = rf(group)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// UpdateInstallation provides a mock function with given fields: installation
func (_m *Store) UpdateInstallation(installation *model.Installation) error {
	ret := _m.Called(installation)

	var r0 error
	if rf, ok := ret.Get(0).(func(*model.Installation) error); ok {
		r0 = rf(installation)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}
