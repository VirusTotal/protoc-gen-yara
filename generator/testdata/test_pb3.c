
/* Generated by the yara-pb compiler. DO NOT EDIT! */
#include <yara/mem.h>
#include <yara/modules.h>
#include "test_pb3.pb-c.h"

#define MODULE_NAME test

static void* _pb_alloc(void *allocator_data, size_t size)
{
  return yr_malloc(size);
}

static void _pb_free(void *allocator_data, void *pointer)
{
  return yr_free(pointer);
}

begin_declarations;
  begin_struct("Struct");
    begin_struct("Enum");
      declare_integer("FIRST");
      declare_integer("SECOND");
    end_struct("Enum");
  end_struct("Struct");
  declare_integer("f_int32");
  declare_integer("f_int64");
  declare_integer("f_sint32");
  declare_integer("f_sint64");
  declare_integer("f_sfixed32");
  declare_integer("f_sfixed64");
  declare_integer("f_bool");
  declare_string("f_string");
  declare_string("f_bytes");
  begin_struct("f_struct");
    declare_string("f_string");
    begin_struct("f_struct");
      declare_integer("f_int32");
      declare_string("f_string");
    end_struct("f_struct");
    declare_integer("enum_");
  end_struct("f_struct");
  declare_integer_dictionary("f_map_int32");
  declare_integer_dictionary("f_map_bool");
  declare_string_dictionary("f_map_string");
  declare_float_dictionary("f_map_float");
  begin_struct_dictionary("f_map_struct");
    declare_integer("f_int32");
    declare_integer("f_int64");
  end_struct_dictionary("f_map_struct");
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

  Root* pb = root__unpack(&allocator, module_data_size, module_data);

  if (pb == NULL)
    return ERROR_INVALID_MODULE_DATA;

  set_integer(0, module_object, "Struct.Enum.FIRST");
  set_integer(1, module_object, "Struct.Enum.SECOND");
  set_integer(pb->f_int32, module_object, "f_int32");
  set_integer(pb->f_int64, module_object, "f_int64");
  set_integer(pb->f_sint32, module_object, "f_sint32");
  set_integer(pb->f_sint64, module_object, "f_sint64");
  set_integer(pb->f_sfixed32, module_object, "f_sfixed32");
  set_integer(pb->f_sfixed64, module_object, "f_sfixed64");
  set_integer(pb->f_bool, module_object, "f_bool");
  set_string(pb->f_string, module_object, "f_string");
  set_sized_string((const char *) pb->f_bytes.data, pb->f_bytes.len, module_object, "f_bytes");

  if (pb->f_struct != NULL) {
    set_string(pb->f_struct->f_string, module_object, "f_struct.f_string");

    if (pb->f_struct->f_struct != NULL) {
      set_integer(pb->f_struct->f_struct->f_int32, module_object, "f_struct.f_struct.f_int32");
      set_string(pb->f_struct->f_struct->f_string, module_object, "f_struct.f_struct.f_string");
    }
    set_integer(pb->f_struct->enum_, module_object, "f_struct.enum_");
  }

  for (int i = 0; i < pb->n_f_map_int32; i++) {

    if (pb->f_map_int32[i] != NULL) {
      set_integer(pb->f_map_int32[i]->value, module_object, "f_map_int32[%s]", pb->f_map_int32[i]->key);
    }
  }

  for (int i = 0; i < pb->n_f_map_bool; i++) {

    if (pb->f_map_bool[i] != NULL) {
      set_integer(pb->f_map_bool[i]->value, module_object, "f_map_bool[%s]", pb->f_map_bool[i]->key);
    }
  }

  for (int i = 0; i < pb->n_f_map_string; i++) {

    if (pb->f_map_string[i] != NULL) {
      set_string(pb->f_map_string[i]->value, module_object, "f_map_string[%s]", pb->f_map_string[i]->key);
    }
  }

  for (int i = 0; i < pb->n_f_map_float; i++) {

    if (pb->f_map_float[i] != NULL) {
      set_float(pb->f_map_float[i]->value, module_object, "f_map_float[%s]", pb->f_map_float[i]->key);
    }
  }

  for (int i = 0; i < pb->n_f_map_struct; i++) {

    if (pb->f_map_struct[i] != NULL) {

      if (pb->f_map_struct[i]->value != NULL) {
        set_integer(pb->f_map_struct[i]->value->f_int32, module_object, "f_map_struct[%s].f_int32", pb->f_map_struct[i]->key);
        set_integer(pb->f_map_struct[i]->value->f_int64, module_object, "f_map_struct[%s].f_int64", pb->f_map_struct[i]->key);
      }
    }
  }


  root__free_unpacked(pb, &allocator);

  return ERROR_SUCCESS;
}