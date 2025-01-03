// Code generated by mockery v2.46.3. DO NOT EDIT.

package foodgroup

import (
	state "github.com/mk6i/retro-aim-server/state"
	mock "github.com/stretchr/testify/mock"
)

// mockSessionRegistry is an autogenerated mock type for the SessionRegistry type
type mockSessionRegistry struct {
	mock.Mock
}

type mockSessionRegistry_Expecter struct {
	mock *mock.Mock
}

func (_m *mockSessionRegistry) EXPECT() *mockSessionRegistry_Expecter {
	return &mockSessionRegistry_Expecter{mock: &_m.Mock}
}

// AddSession provides a mock function with given fields: screenName
func (_m *mockSessionRegistry) AddSession(screenName state.DisplayScreenName) *state.Session {
	ret := _m.Called(screenName)

	if len(ret) == 0 {
		panic("no return value specified for AddSession")
	}

	var r0 *state.Session
	if rf, ok := ret.Get(0).(func(state.DisplayScreenName) *state.Session); ok {
		r0 = rf(screenName)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*state.Session)
		}
	}

	return r0
}

// mockSessionRegistry_AddSession_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'AddSession'
type mockSessionRegistry_AddSession_Call struct {
	*mock.Call
}

// AddSession is a helper method to define mock.On call
//   - screenName state.DisplayScreenName
func (_e *mockSessionRegistry_Expecter) AddSession(screenName interface{}) *mockSessionRegistry_AddSession_Call {
	return &mockSessionRegistry_AddSession_Call{Call: _e.mock.On("AddSession", screenName)}
}

func (_c *mockSessionRegistry_AddSession_Call) Run(run func(screenName state.DisplayScreenName)) *mockSessionRegistry_AddSession_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(state.DisplayScreenName))
	})
	return _c
}

func (_c *mockSessionRegistry_AddSession_Call) Return(_a0 *state.Session) *mockSessionRegistry_AddSession_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *mockSessionRegistry_AddSession_Call) RunAndReturn(run func(state.DisplayScreenName) *state.Session) *mockSessionRegistry_AddSession_Call {
	_c.Call.Return(run)
	return _c
}

// RemoveSession provides a mock function with given fields: sess
func (_m *mockSessionRegistry) RemoveSession(sess *state.Session) {
	_m.Called(sess)
}

// mockSessionRegistry_RemoveSession_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'RemoveSession'
type mockSessionRegistry_RemoveSession_Call struct {
	*mock.Call
}

// RemoveSession is a helper method to define mock.On call
//   - sess *state.Session
func (_e *mockSessionRegistry_Expecter) RemoveSession(sess interface{}) *mockSessionRegistry_RemoveSession_Call {
	return &mockSessionRegistry_RemoveSession_Call{Call: _e.mock.On("RemoveSession", sess)}
}

func (_c *mockSessionRegistry_RemoveSession_Call) Run(run func(sess *state.Session)) *mockSessionRegistry_RemoveSession_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(*state.Session))
	})
	return _c
}

func (_c *mockSessionRegistry_RemoveSession_Call) Return() *mockSessionRegistry_RemoveSession_Call {
	_c.Call.Return()
	return _c
}

func (_c *mockSessionRegistry_RemoveSession_Call) RunAndReturn(run func(*state.Session)) *mockSessionRegistry_RemoveSession_Call {
	_c.Call.Return(run)
	return _c
}

// newMockSessionRegistry creates a new instance of mockSessionRegistry. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func newMockSessionRegistry(t interface {
	mock.TestingT
	Cleanup(func())
}) *mockSessionRegistry {
	mock := &mockSessionRegistry{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
