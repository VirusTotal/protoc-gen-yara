package generator

import "html/template"

const moduleTemplate = `
/* Generated by the protoc-gen-yara. DO NOT EDIT! */
#include <yara/mem.h>
#include <yara/modules.h>
#include "{{ .IncludeName }}.pb-c.h"

#define MODULE_NAME {{ .ModuleName }}

static void* _pb_alloc(void *allocator_data, size_t size)
{
  return yr_malloc(size);
}

static void _pb_free(void *allocator_data, void *pointer)
{
  return yr_free(pointer);
}

begin_declarations;
{{ .Declarations -}}
end_declarations;

int module_initialize(
    YR_MODULE* module)
{
  return ERROR_SUCCESS;
}

int module_finalize(
    YR_MODULE* module)
{
  return ERROR_SUCCESS;
}

int module_unload(
    YR_OBJECT* module_object)
{
  return ERROR_SUCCESS;
}

int module_load(
    YR_SCAN_CONTEXT* context,
    YR_OBJECT* module_object,
    void* module_data,
    size_t module_data_size)
{
  ProtobufCAllocator allocator;

  allocator.alloc = _pb_alloc;
  allocator.free = _pb_free;

  if (module_data == NULL)
    return ERROR_SUCCESS;

  {{ .RootStruct }}* pb = {{ .RootStruct | ToLower }}__unpack(&allocator, module_data_size, module_data);

  if (pb == NULL)
    return ERROR_INVALID_MODULE_DATA;

{{ .Initializations }}

  {{ .RootStruct | ToLower }}__free_unpacked(pb, &allocator);

  return ERROR_SUCCESS;
}
`

type templateData struct {
	ModuleName      string
	IncludeName     string
	RootStruct      string
	Declarations    template.HTML
	Initializations template.HTML
}
