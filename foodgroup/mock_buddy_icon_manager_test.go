// Code generated by mockery v2.52.1. DO NOT EDIT.

package foodgroup

import (
	context "context"

	state "github.com/mk6i/retro-aim-server/state"
	mock "github.com/stretchr/testify/mock"

	wire "github.com/mk6i/retro-aim-server/wire"
)

// mockBuddyIconManager is an autogenerated mock type for the BuddyIconManager type
type mockBuddyIconManager struct {
	mock.Mock
}

type mockBuddyIconManager_Expecter struct {
	mock *mock.Mock
}

func (_m *mockBuddyIconManager) EXPECT() *mockBuddyIconManager_Expecter {
	return &mockBuddyIconManager_Expecter{mock: &_m.Mock}
}

// BuddyIcon provides a mock function with given fields: ctx, md5
func (_m *mockBuddyIconManager) BuddyIcon(ctx context.Context, md5 []byte) ([]byte, error) {
	ret := _m.Called(ctx, md5)

	if len(ret) == 0 {
		panic("no return value specified for BuddyIcon")
	}

	var r0 []byte
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, []byte) ([]byte, error)); ok {
		return rf(ctx, md5)
	}
	if rf, ok := ret.Get(0).(func(context.Context, []byte) []byte); ok {
		r0 = rf(ctx, md5)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]byte)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, []byte) error); ok {
		r1 = rf(ctx, md5)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// mockBuddyIconManager_BuddyIcon_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'BuddyIcon'
type mockBuddyIconManager_BuddyIcon_Call struct {
	*mock.Call
}

// BuddyIcon is a helper method to define mock.On call
//   - ctx context.Context
//   - md5 []byte
func (_e *mockBuddyIconManager_Expecter) BuddyIcon(ctx interface{}, md5 interface{}) *mockBuddyIconManager_BuddyIcon_Call {
	return &mockBuddyIconManager_BuddyIcon_Call{Call: _e.mock.On("BuddyIcon", ctx, md5)}
}

func (_c *mockBuddyIconManager_BuddyIcon_Call) Run(run func(ctx context.Context, md5 []byte)) *mockBuddyIconManager_BuddyIcon_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].([]byte))
	})
	return _c
}

func (_c *mockBuddyIconManager_BuddyIcon_Call) Return(_a0 []byte, _a1 error) *mockBuddyIconManager_BuddyIcon_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *mockBuddyIconManager_BuddyIcon_Call) RunAndReturn(run func(context.Context, []byte) ([]byte, error)) *mockBuddyIconManager_BuddyIcon_Call {
	_c.Call.Return(run)
	return _c
}

// BuddyIconMetadata provides a mock function with given fields: ctx, screenName
func (_m *mockBuddyIconManager) BuddyIconMetadata(ctx context.Context, screenName state.IdentScreenName) (*wire.BARTID, error) {
	ret := _m.Called(ctx, screenName)

	if len(ret) == 0 {
		panic("no return value specified for BuddyIconMetadata")
	}

	var r0 *wire.BARTID
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, state.IdentScreenName) (*wire.BARTID, error)); ok {
		return rf(ctx, screenName)
	}
	if rf, ok := ret.Get(0).(func(context.Context, state.IdentScreenName) *wire.BARTID); ok {
		r0 = rf(ctx, screenName)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*wire.BARTID)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, state.IdentScreenName) error); ok {
		r1 = rf(ctx, screenName)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// mockBuddyIconManager_BuddyIconMetadata_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'BuddyIconMetadata'
type mockBuddyIconManager_BuddyIconMetadata_Call struct {
	*mock.Call
}

// BuddyIconMetadata is a helper method to define mock.On call
//   - ctx context.Context
//   - screenName state.IdentScreenName
func (_e *mockBuddyIconManager_Expecter) BuddyIconMetadata(ctx interface{}, screenName interface{}) *mockBuddyIconManager_BuddyIconMetadata_Call {
	return &mockBuddyIconManager_BuddyIconMetadata_Call{Call: _e.mock.On("BuddyIconMetadata", ctx, screenName)}
}

func (_c *mockBuddyIconManager_BuddyIconMetadata_Call) Run(run func(ctx context.Context, screenName state.IdentScreenName)) *mockBuddyIconManager_BuddyIconMetadata_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(state.IdentScreenName))
	})
	return _c
}

func (_c *mockBuddyIconManager_BuddyIconMetadata_Call) Return(_a0 *wire.BARTID, _a1 error) *mockBuddyIconManager_BuddyIconMetadata_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *mockBuddyIconManager_BuddyIconMetadata_Call) RunAndReturn(run func(context.Context, state.IdentScreenName) (*wire.BARTID, error)) *mockBuddyIconManager_BuddyIconMetadata_Call {
	_c.Call.Return(run)
	return _c
}

// SetBuddyIcon provides a mock function with given fields: ctx, md5, image
func (_m *mockBuddyIconManager) SetBuddyIcon(ctx context.Context, md5 []byte, image []byte) error {
	ret := _m.Called(ctx, md5, image)

	if len(ret) == 0 {
		panic("no return value specified for SetBuddyIcon")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, []byte, []byte) error); ok {
		r0 = rf(ctx, md5, image)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// mockBuddyIconManager_SetBuddyIcon_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'SetBuddyIcon'
type mockBuddyIconManager_SetBuddyIcon_Call struct {
	*mock.Call
}

// SetBuddyIcon is a helper method to define mock.On call
//   - ctx context.Context
//   - md5 []byte
//   - image []byte
func (_e *mockBuddyIconManager_Expecter) SetBuddyIcon(ctx interface{}, md5 interface{}, image interface{}) *mockBuddyIconManager_SetBuddyIcon_Call {
	return &mockBuddyIconManager_SetBuddyIcon_Call{Call: _e.mock.On("SetBuddyIcon", ctx, md5, image)}
}

func (_c *mockBuddyIconManager_SetBuddyIcon_Call) Run(run func(ctx context.Context, md5 []byte, image []byte)) *mockBuddyIconManager_SetBuddyIcon_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].([]byte), args[2].([]byte))
	})
	return _c
}

func (_c *mockBuddyIconManager_SetBuddyIcon_Call) Return(_a0 error) *mockBuddyIconManager_SetBuddyIcon_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *mockBuddyIconManager_SetBuddyIcon_Call) RunAndReturn(run func(context.Context, []byte, []byte) error) *mockBuddyIconManager_SetBuddyIcon_Call {
	_c.Call.Return(run)
	return _c
}

// newMockBuddyIconManager creates a new instance of mockBuddyIconManager. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func newMockBuddyIconManager(t interface {
	mock.TestingT
	Cleanup(func())
}) *mockBuddyIconManager {
	mock := &mockBuddyIconManager{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
