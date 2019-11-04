
protoc-gen-yara
-----------------

`protoc-gen-yara` is a plugin for `protoc`, the [Google Protocol Buffer](https://developers.google.com/protocol-buffers) compiler. It takes a protocol buffer description file (.proto) and automatically generates the source code for a YARA module that accepts data encoded in the format defined by the procol buffer. By using the generated module you can create YARA rules that rely on your custom-defined data structures.

For example, let's suppose that you have the following protocol buffer definition:

```protobuf
syntax = "proto3";

import "yara.proto";

option (yara.module_options) = {
  name : "pb_customer"
  top_level_message: "Customer";
};

message Customer {
  string name = 1;
  int32 age = 2;
  repeated CreditCard credit_cards = 3;
}

message CreditCard {
  string number = 1;
  message Expiration {
    int32 year = 1;
    int32 month = 2;
  }
  Expiration expiration = 2;
  enum Status {
    VALID = 0;
    CANCELLED = 1;
  }
  Status status = 3;
}
```


From the above protobuf definition you can generate a YARA module `pb_customer` that will receive data encoded as the `Customer` message and use it for creating rules like the following ones:

```
import "pb_customer"

rule customer_under_25 {
condition:
	pb_customer.age < 25
}

```


Notice that the protobuf definition includes the following snippet:

```protobuf
import "yara.proto";

option (yara.module_options) = {
  name : "pb_customer"
  root_message: "Customer";
};
```


This is required for `protoc-gen-yara` to be able to generate the YARA module. The `yara.proto` file contains the definitions for the module's options, like `name` and `root_message`, so it must be imported in your proto. The `name` option contains the module's name (the one that you will later use in `import` statements in your YARA rules), while `root_message` is the name of a message defining the top-level structure for the module. You can have multiple message definitions in your proto file, but only one of them can be the root message. In the example above, as the root message is `Customer` and the module is named `pb_customer` you can access fields `name` and `age` as `pb_customer.name` and `pb_customer.age` respectively.
