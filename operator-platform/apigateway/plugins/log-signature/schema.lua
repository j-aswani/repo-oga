
return {
  name = "log-signature",
  fields = {
    { config = {
        type = "record",
        fields = {
          { path = { type = "string",
                     required = true,
                     match = [[^[^*&%%\`]+$]],
                     err = "not a valid filename",
          }, },
          { signature_header_name = { type = "string",
                     required = false,
                     default = "x-signature",
          }, },
        },
    }, },
  }
}