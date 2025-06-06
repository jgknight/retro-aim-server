// Code generated by mockery v2.53.3. DO NOT EDIT.

package toc

import (
	context "context"

	state "github.com/mk6i/retro-aim-server/state"
	mock "github.com/stretchr/testify/mock"
)

// mockBuddyListRegistry is an autogenerated mock type for the BuddyListRegistry type
type mockBuddyListRegistry struct {
	mock.Mock
}

type mockBuddyListRegistry_Expecter struct {
	mock *mock.Mock
}

func (_m *mockBuddyListRegistry) EXPECT() *mockBuddyListRegistry_Expecter {
	return &mockBuddyListRegistry_Expecter{mock: &_m.Mock}
}

// RegisterBuddyList provides a mock function with given fields: ctx, user
func (_m *mockBuddyListRegistry) RegisterBuddyList(ctx context.Context, user state.IdentScreenName) error {
	ret := _m.Called(ctx, user)

	if len(ret) == 0 {
		panic("no return value specified for RegisterBuddyList")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, state.IdentScreenName) error); ok {
		r0 = rf(ctx, user)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// mockBuddyListRegistry_RegisterBuddyList_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'RegisterBuddyList'
type mockBuddyListRegistry_RegisterBuddyList_Call struct {
	*mock.Call
}

// RegisterBuddyList is a helper method to define mock.On call
//   - ctx context.Context
//   - user state.IdentScreenName
func (_e *mockBuddyListRegistry_Expecter) RegisterBuddyList(ctx interface{}, user interface{}) *mockBuddyListRegistry_RegisterBuddyList_Call {
	return &mockBuddyListRegistry_RegisterBuddyList_Call{Call: _e.mock.On("RegisterBuddyList", ctx, user)}
}

func (_c *mockBuddyListRegistry_RegisterBuddyList_Call) Run(run func(ctx context.Context, user state.IdentScreenName)) *mockBuddyListRegistry_RegisterBuddyList_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(state.IdentScreenName))
	})
	return _c
}

func (_c *mockBuddyListRegistry_RegisterBuddyList_Call) Return(_a0 error) *mockBuddyListRegistry_RegisterBuddyList_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *mockBuddyListRegistry_RegisterBuddyList_Call) RunAndReturn(run func(context.Context, state.IdentScreenName) error) *mockBuddyListRegistry_RegisterBuddyList_Call {
	_c.Call.Return(run)
	return _c
}

// UnregisterBuddyList provides a mock function with given fields: ctx, user
func (_m *mockBuddyListRegistry) UnregisterBuddyList(ctx context.Context, user state.IdentScreenName) error {
	ret := _m.Called(ctx, user)

	if len(ret) == 0 {
		panic("no return value specified for UnregisterBuddyList")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, state.IdentScreenName) error); ok {
		r0 = rf(ctx, user)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// mockBuddyListRegistry_UnregisterBuddyList_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'UnregisterBuddyList'
type mockBuddyListRegistry_UnregisterBuddyList_Call struct {
	*mock.Call
}

// UnregisterBuddyList is a helper method to define mock.On call
//   - ctx context.Context
//   - user state.IdentScreenName
func (_e *mockBuddyListRegistry_Expecter) UnregisterBuddyList(ctx interface{}, user interface{}) *mockBuddyListRegistry_UnregisterBuddyList_Call {
	return &mockBuddyListRegistry_UnregisterBuddyList_Call{Call: _e.mock.On("UnregisterBuddyList", ctx, user)}
}

func (_c *mockBuddyListRegistry_UnregisterBuddyList_Call) Run(run func(ctx context.Context, user state.IdentScreenName)) *mockBuddyListRegistry_UnregisterBuddyList_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(state.IdentScreenName))
	})
	return _c
}

func (_c *mockBuddyListRegistry_UnregisterBuddyList_Call) Return(_a0 error) *mockBuddyListRegistry_UnregisterBuddyList_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *mockBuddyListRegistry_UnregisterBuddyList_Call) RunAndReturn(run func(context.Context, state.IdentScreenName) error) *mockBuddyListRegistry_UnregisterBuddyList_Call {
	_c.Call.Return(run)
	return _c
}

// newMockBuddyListRegistry creates a new instance of mockBuddyListRegistry. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func newMockBuddyListRegistry(t interface {
	mock.TestingT
	Cleanup(func())
}) *mockBuddyListRegistry {
	mock := &mockBuddyListRegistry{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
