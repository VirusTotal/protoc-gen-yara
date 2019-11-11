package generator

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSnakeCase(t *testing.T) {

	assert.Equal(t, "foo_bar", CamelToSnakeCase("FooBar"))
	assert.Equal(t, "_foo_bar", CamelToSnakeCase("_FooBar"))
	assert.Equal(t, "foo_bar_baz", CamelToSnakeCase("FooBar_Baz"))
	assert.Equal(t, "foo0_bar", CamelToSnakeCase("Foo0Bar"))
	assert.Equal(t, "foo_bar_baz", CamelToSnakeCase("Foo_Bar_Baz"))
}
