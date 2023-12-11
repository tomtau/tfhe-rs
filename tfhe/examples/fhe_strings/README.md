# fhe_strings: TFHE-rs encrypted string library bounty

## Run from command line

```bash
make fhe_strings
```

### Parameters

- `FHE_STRINGS_INPUT_STRING`: string to encrypt and do operations on
- `FHE_STRINGS_INPUT_STRING_PADDING`: padding for `FHE_STRINGS_INPUT_STRING` (if any)
- `FHE_STRINGS_INPUT_PATTERN`: pattern to use in some operations
- `FHE_STRINGS_INPUT_PATTERN_PADDING`: padding for `FHE_STRINGS_INPUT_PATTERN` (if any)
- `FHE_STRINGS_INPUT_STRING2`: the second string to use in some operations
- `FHE_STRINGS_INPUT_STRING2_PADDING`: padding for `FHE_STRINGS_INPUT_STRING2` (if any)
- `FHE_STRINGS_INPUT_NUMBER`: the number to use in some operations
- `FHE_STRINGS_SKIP_REPEAT_ENCRYPTED_NUMBER`: whether to skip of `repeat` operation with an encrypted number
- `FHE_STRINGS_FUNCTION`: which function to run (if not set, it'll run all)

## Run tests

Run tests for specific functions:

```bash
FHE_STRINGS_TEST=<test filter> make fhe_strings_test
```

Run all tests:

```bash
make fhe_strings_test_per_mod
```
