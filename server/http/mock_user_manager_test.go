// Code generated by mockery v2.53.3. DO NOT EDIT.

package http

import (
	context "context"

	state "github.com/mk6i/retro-aim-server/state"
	mock "github.com/stretchr/testify/mock"
)

// mockUserManager is an autogenerated mock type for the UserManager type
type mockUserManager struct {
	mock.Mock
}

type mockUserManager_Expecter struct {
	mock *mock.Mock
}

func (_m *mockUserManager) EXPECT() *mockUserManager_Expecter {
	return &mockUserManager_Expecter{mock: &_m.Mock}
}

// AllUsers provides a mock function with given fields: ctx
func (_m *mockUserManager) AllUsers(ctx context.Context) ([]state.User, error) {
	ret := _m.Called(ctx)

	if len(ret) == 0 {
		panic("no return value specified for AllUsers")
	}

	var r0 []state.User
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context) ([]state.User, error)); ok {
		return rf(ctx)
	}
	if rf, ok := ret.Get(0).(func(context.Context) []state.User); ok {
		r0 = rf(ctx)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]state.User)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context) error); ok {
		r1 = rf(ctx)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// mockUserManager_AllUsers_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'AllUsers'
type mockUserManager_AllUsers_Call struct {
	*mock.Call
}

// AllUsers is a helper method to define mock.On call
//   - ctx context.Context
func (_e *mockUserManager_Expecter) AllUsers(ctx interface{}) *mockUserManager_AllUsers_Call {
	return &mockUserManager_AllUsers_Call{Call: _e.mock.On("AllUsers", ctx)}
}

func (_c *mockUserManager_AllUsers_Call) Run(run func(ctx context.Context)) *mockUserManager_AllUsers_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context))
	})
	return _c
}

func (_c *mockUserManager_AllUsers_Call) Return(_a0 []state.User, _a1 error) *mockUserManager_AllUsers_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *mockUserManager_AllUsers_Call) RunAndReturn(run func(context.Context) ([]state.User, error)) *mockUserManager_AllUsers_Call {
	_c.Call.Return(run)
	return _c
}

// DeleteUser provides a mock function with given fields: ctx, screenName
func (_m *mockUserManager) DeleteUser(ctx context.Context, screenName state.IdentScreenName) error {
	ret := _m.Called(ctx, screenName)

	if len(ret) == 0 {
		panic("no return value specified for DeleteUser")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, state.IdentScreenName) error); ok {
		r0 = rf(ctx, screenName)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// mockUserManager_DeleteUser_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'DeleteUser'
type mockUserManager_DeleteUser_Call struct {
	*mock.Call
}

// DeleteUser is a helper method to define mock.On call
//   - ctx context.Context
//   - screenName state.IdentScreenName
func (_e *mockUserManager_Expecter) DeleteUser(ctx interface{}, screenName interface{}) *mockUserManager_DeleteUser_Call {
	return &mockUserManager_DeleteUser_Call{Call: _e.mock.On("DeleteUser", ctx, screenName)}
}

func (_c *mockUserManager_DeleteUser_Call) Run(run func(ctx context.Context, screenName state.IdentScreenName)) *mockUserManager_DeleteUser_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(state.IdentScreenName))
	})
	return _c
}

func (_c *mockUserManager_DeleteUser_Call) Return(_a0 error) *mockUserManager_DeleteUser_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *mockUserManager_DeleteUser_Call) RunAndReturn(run func(context.Context, state.IdentScreenName) error) *mockUserManager_DeleteUser_Call {
	_c.Call.Return(run)
	return _c
}

// InsertUser provides a mock function with given fields: ctx, u
func (_m *mockUserManager) InsertUser(ctx context.Context, u state.User) error {
	ret := _m.Called(ctx, u)

	if len(ret) == 0 {
		panic("no return value specified for InsertUser")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, state.User) error); ok {
		r0 = rf(ctx, u)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// mockUserManager_InsertUser_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'InsertUser'
type mockUserManager_InsertUser_Call struct {
	*mock.Call
}

// InsertUser is a helper method to define mock.On call
//   - ctx context.Context
//   - u state.User
func (_e *mockUserManager_Expecter) InsertUser(ctx interface{}, u interface{}) *mockUserManager_InsertUser_Call {
	return &mockUserManager_InsertUser_Call{Call: _e.mock.On("InsertUser", ctx, u)}
}

func (_c *mockUserManager_InsertUser_Call) Run(run func(ctx context.Context, u state.User)) *mockUserManager_InsertUser_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(state.User))
	})
	return _c
}

func (_c *mockUserManager_InsertUser_Call) Return(_a0 error) *mockUserManager_InsertUser_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *mockUserManager_InsertUser_Call) RunAndReturn(run func(context.Context, state.User) error) *mockUserManager_InsertUser_Call {
	_c.Call.Return(run)
	return _c
}

// SetUserPassword provides a mock function with given fields: ctx, screenName, newPassword
func (_m *mockUserManager) SetUserPassword(ctx context.Context, screenName state.IdentScreenName, newPassword string) error {
	ret := _m.Called(ctx, screenName, newPassword)

	if len(ret) == 0 {
		panic("no return value specified for SetUserPassword")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, state.IdentScreenName, string) error); ok {
		r0 = rf(ctx, screenName, newPassword)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// mockUserManager_SetUserPassword_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'SetUserPassword'
type mockUserManager_SetUserPassword_Call struct {
	*mock.Call
}

// SetUserPassword is a helper method to define mock.On call
//   - ctx context.Context
//   - screenName state.IdentScreenName
//   - newPassword string
func (_e *mockUserManager_Expecter) SetUserPassword(ctx interface{}, screenName interface{}, newPassword interface{}) *mockUserManager_SetUserPassword_Call {
	return &mockUserManager_SetUserPassword_Call{Call: _e.mock.On("SetUserPassword", ctx, screenName, newPassword)}
}

func (_c *mockUserManager_SetUserPassword_Call) Run(run func(ctx context.Context, screenName state.IdentScreenName, newPassword string)) *mockUserManager_SetUserPassword_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(state.IdentScreenName), args[2].(string))
	})
	return _c
}

func (_c *mockUserManager_SetUserPassword_Call) Return(_a0 error) *mockUserManager_SetUserPassword_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *mockUserManager_SetUserPassword_Call) RunAndReturn(run func(context.Context, state.IdentScreenName, string) error) *mockUserManager_SetUserPassword_Call {
	_c.Call.Return(run)
	return _c
}

// User provides a mock function with given fields: ctx, screenName
func (_m *mockUserManager) User(ctx context.Context, screenName state.IdentScreenName) (*state.User, error) {
	ret := _m.Called(ctx, screenName)

	if len(ret) == 0 {
		panic("no return value specified for User")
	}

	var r0 *state.User
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, state.IdentScreenName) (*state.User, error)); ok {
		return rf(ctx, screenName)
	}
	if rf, ok := ret.Get(0).(func(context.Context, state.IdentScreenName) *state.User); ok {
		r0 = rf(ctx, screenName)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*state.User)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, state.IdentScreenName) error); ok {
		r1 = rf(ctx, screenName)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// mockUserManager_User_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'User'
type mockUserManager_User_Call struct {
	*mock.Call
}

// User is a helper method to define mock.On call
//   - ctx context.Context
//   - screenName state.IdentScreenName
func (_e *mockUserManager_Expecter) User(ctx interface{}, screenName interface{}) *mockUserManager_User_Call {
	return &mockUserManager_User_Call{Call: _e.mock.On("User", ctx, screenName)}
}

func (_c *mockUserManager_User_Call) Run(run func(ctx context.Context, screenName state.IdentScreenName)) *mockUserManager_User_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(state.IdentScreenName))
	})
	return _c
}

func (_c *mockUserManager_User_Call) Return(_a0 *state.User, _a1 error) *mockUserManager_User_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *mockUserManager_User_Call) RunAndReturn(run func(context.Context, state.IdentScreenName) (*state.User, error)) *mockUserManager_User_Call {
	_c.Call.Return(run)
	return _c
}

// newMockUserManager creates a new instance of mockUserManager. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func newMockUserManager(t interface {
	mock.TestingT
	Cleanup(func())
}) *mockUserManager {
	mock := &mockUserManager{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
