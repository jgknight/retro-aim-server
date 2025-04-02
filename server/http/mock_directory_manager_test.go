// Code generated by mockery v2.52.1. DO NOT EDIT.

package http

import (
	context "context"

	state "github.com/mk6i/retro-aim-server/state"
	mock "github.com/stretchr/testify/mock"
)

// mockDirectoryManager is an autogenerated mock type for the DirectoryManager type
type mockDirectoryManager struct {
	mock.Mock
}

type mockDirectoryManager_Expecter struct {
	mock *mock.Mock
}

func (_m *mockDirectoryManager) EXPECT() *mockDirectoryManager_Expecter {
	return &mockDirectoryManager_Expecter{mock: &_m.Mock}
}

// Categories provides a mock function with given fields: ctx
func (_m *mockDirectoryManager) Categories(ctx context.Context) ([]state.Category, error) {
	ret := _m.Called(ctx)

	if len(ret) == 0 {
		panic("no return value specified for Categories")
	}

	var r0 []state.Category
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context) ([]state.Category, error)); ok {
		return rf(ctx)
	}
	if rf, ok := ret.Get(0).(func(context.Context) []state.Category); ok {
		r0 = rf(ctx)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]state.Category)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context) error); ok {
		r1 = rf(ctx)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// mockDirectoryManager_Categories_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Categories'
type mockDirectoryManager_Categories_Call struct {
	*mock.Call
}

// Categories is a helper method to define mock.On call
//   - ctx context.Context
func (_e *mockDirectoryManager_Expecter) Categories(ctx interface{}) *mockDirectoryManager_Categories_Call {
	return &mockDirectoryManager_Categories_Call{Call: _e.mock.On("Categories", ctx)}
}

func (_c *mockDirectoryManager_Categories_Call) Run(run func(ctx context.Context)) *mockDirectoryManager_Categories_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context))
	})
	return _c
}

func (_c *mockDirectoryManager_Categories_Call) Return(_a0 []state.Category, _a1 error) *mockDirectoryManager_Categories_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *mockDirectoryManager_Categories_Call) RunAndReturn(run func(context.Context) ([]state.Category, error)) *mockDirectoryManager_Categories_Call {
	_c.Call.Return(run)
	return _c
}

// CreateCategory provides a mock function with given fields: ctx, name
func (_m *mockDirectoryManager) CreateCategory(ctx context.Context, name string) (state.Category, error) {
	ret := _m.Called(ctx, name)

	if len(ret) == 0 {
		panic("no return value specified for CreateCategory")
	}

	var r0 state.Category
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string) (state.Category, error)); ok {
		return rf(ctx, name)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string) state.Category); ok {
		r0 = rf(ctx, name)
	} else {
		r0 = ret.Get(0).(state.Category)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, name)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// mockDirectoryManager_CreateCategory_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'CreateCategory'
type mockDirectoryManager_CreateCategory_Call struct {
	*mock.Call
}

// CreateCategory is a helper method to define mock.On call
//   - ctx context.Context
//   - name string
func (_e *mockDirectoryManager_Expecter) CreateCategory(ctx interface{}, name interface{}) *mockDirectoryManager_CreateCategory_Call {
	return &mockDirectoryManager_CreateCategory_Call{Call: _e.mock.On("CreateCategory", ctx, name)}
}

func (_c *mockDirectoryManager_CreateCategory_Call) Run(run func(ctx context.Context, name string)) *mockDirectoryManager_CreateCategory_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string))
	})
	return _c
}

func (_c *mockDirectoryManager_CreateCategory_Call) Return(_a0 state.Category, _a1 error) *mockDirectoryManager_CreateCategory_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *mockDirectoryManager_CreateCategory_Call) RunAndReturn(run func(context.Context, string) (state.Category, error)) *mockDirectoryManager_CreateCategory_Call {
	_c.Call.Return(run)
	return _c
}

// CreateKeyword provides a mock function with given fields: ctx, name, categoryID
func (_m *mockDirectoryManager) CreateKeyword(ctx context.Context, name string, categoryID uint8) (state.Keyword, error) {
	ret := _m.Called(ctx, name, categoryID)

	if len(ret) == 0 {
		panic("no return value specified for CreateKeyword")
	}

	var r0 state.Keyword
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, uint8) (state.Keyword, error)); ok {
		return rf(ctx, name, categoryID)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, uint8) state.Keyword); ok {
		r0 = rf(ctx, name, categoryID)
	} else {
		r0 = ret.Get(0).(state.Keyword)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, uint8) error); ok {
		r1 = rf(ctx, name, categoryID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// mockDirectoryManager_CreateKeyword_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'CreateKeyword'
type mockDirectoryManager_CreateKeyword_Call struct {
	*mock.Call
}

// CreateKeyword is a helper method to define mock.On call
//   - ctx context.Context
//   - name string
//   - categoryID uint8
func (_e *mockDirectoryManager_Expecter) CreateKeyword(ctx interface{}, name interface{}, categoryID interface{}) *mockDirectoryManager_CreateKeyword_Call {
	return &mockDirectoryManager_CreateKeyword_Call{Call: _e.mock.On("CreateKeyword", ctx, name, categoryID)}
}

func (_c *mockDirectoryManager_CreateKeyword_Call) Run(run func(ctx context.Context, name string, categoryID uint8)) *mockDirectoryManager_CreateKeyword_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string), args[2].(uint8))
	})
	return _c
}

func (_c *mockDirectoryManager_CreateKeyword_Call) Return(_a0 state.Keyword, _a1 error) *mockDirectoryManager_CreateKeyword_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *mockDirectoryManager_CreateKeyword_Call) RunAndReturn(run func(context.Context, string, uint8) (state.Keyword, error)) *mockDirectoryManager_CreateKeyword_Call {
	_c.Call.Return(run)
	return _c
}

// DeleteCategory provides a mock function with given fields: ctx, categoryID
func (_m *mockDirectoryManager) DeleteCategory(ctx context.Context, categoryID uint8) error {
	ret := _m.Called(ctx, categoryID)

	if len(ret) == 0 {
		panic("no return value specified for DeleteCategory")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, uint8) error); ok {
		r0 = rf(ctx, categoryID)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// mockDirectoryManager_DeleteCategory_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'DeleteCategory'
type mockDirectoryManager_DeleteCategory_Call struct {
	*mock.Call
}

// DeleteCategory is a helper method to define mock.On call
//   - ctx context.Context
//   - categoryID uint8
func (_e *mockDirectoryManager_Expecter) DeleteCategory(ctx interface{}, categoryID interface{}) *mockDirectoryManager_DeleteCategory_Call {
	return &mockDirectoryManager_DeleteCategory_Call{Call: _e.mock.On("DeleteCategory", ctx, categoryID)}
}

func (_c *mockDirectoryManager_DeleteCategory_Call) Run(run func(ctx context.Context, categoryID uint8)) *mockDirectoryManager_DeleteCategory_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(uint8))
	})
	return _c
}

func (_c *mockDirectoryManager_DeleteCategory_Call) Return(_a0 error) *mockDirectoryManager_DeleteCategory_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *mockDirectoryManager_DeleteCategory_Call) RunAndReturn(run func(context.Context, uint8) error) *mockDirectoryManager_DeleteCategory_Call {
	_c.Call.Return(run)
	return _c
}

// DeleteKeyword provides a mock function with given fields: ctx, id
func (_m *mockDirectoryManager) DeleteKeyword(ctx context.Context, id uint8) error {
	ret := _m.Called(ctx, id)

	if len(ret) == 0 {
		panic("no return value specified for DeleteKeyword")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, uint8) error); ok {
		r0 = rf(ctx, id)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// mockDirectoryManager_DeleteKeyword_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'DeleteKeyword'
type mockDirectoryManager_DeleteKeyword_Call struct {
	*mock.Call
}

// DeleteKeyword is a helper method to define mock.On call
//   - ctx context.Context
//   - id uint8
func (_e *mockDirectoryManager_Expecter) DeleteKeyword(ctx interface{}, id interface{}) *mockDirectoryManager_DeleteKeyword_Call {
	return &mockDirectoryManager_DeleteKeyword_Call{Call: _e.mock.On("DeleteKeyword", ctx, id)}
}

func (_c *mockDirectoryManager_DeleteKeyword_Call) Run(run func(ctx context.Context, id uint8)) *mockDirectoryManager_DeleteKeyword_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(uint8))
	})
	return _c
}

func (_c *mockDirectoryManager_DeleteKeyword_Call) Return(_a0 error) *mockDirectoryManager_DeleteKeyword_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *mockDirectoryManager_DeleteKeyword_Call) RunAndReturn(run func(context.Context, uint8) error) *mockDirectoryManager_DeleteKeyword_Call {
	_c.Call.Return(run)
	return _c
}

// KeywordsByCategory provides a mock function with given fields: ctx, categoryID
func (_m *mockDirectoryManager) KeywordsByCategory(ctx context.Context, categoryID uint8) ([]state.Keyword, error) {
	ret := _m.Called(ctx, categoryID)

	if len(ret) == 0 {
		panic("no return value specified for KeywordsByCategory")
	}

	var r0 []state.Keyword
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, uint8) ([]state.Keyword, error)); ok {
		return rf(ctx, categoryID)
	}
	if rf, ok := ret.Get(0).(func(context.Context, uint8) []state.Keyword); ok {
		r0 = rf(ctx, categoryID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]state.Keyword)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, uint8) error); ok {
		r1 = rf(ctx, categoryID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// mockDirectoryManager_KeywordsByCategory_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'KeywordsByCategory'
type mockDirectoryManager_KeywordsByCategory_Call struct {
	*mock.Call
}

// KeywordsByCategory is a helper method to define mock.On call
//   - ctx context.Context
//   - categoryID uint8
func (_e *mockDirectoryManager_Expecter) KeywordsByCategory(ctx interface{}, categoryID interface{}) *mockDirectoryManager_KeywordsByCategory_Call {
	return &mockDirectoryManager_KeywordsByCategory_Call{Call: _e.mock.On("KeywordsByCategory", ctx, categoryID)}
}

func (_c *mockDirectoryManager_KeywordsByCategory_Call) Run(run func(ctx context.Context, categoryID uint8)) *mockDirectoryManager_KeywordsByCategory_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(uint8))
	})
	return _c
}

func (_c *mockDirectoryManager_KeywordsByCategory_Call) Return(_a0 []state.Keyword, _a1 error) *mockDirectoryManager_KeywordsByCategory_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *mockDirectoryManager_KeywordsByCategory_Call) RunAndReturn(run func(context.Context, uint8) ([]state.Keyword, error)) *mockDirectoryManager_KeywordsByCategory_Call {
	_c.Call.Return(run)
	return _c
}

// newMockDirectoryManager creates a new instance of mockDirectoryManager. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func newMockDirectoryManager(t interface {
	mock.TestingT
	Cleanup(func())
}) *mockDirectoryManager {
	mock := &mockDirectoryManager{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
