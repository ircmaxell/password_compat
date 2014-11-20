CHANGELOG
=========

This changelog references the relevant changes (bug and security fixes) done in version 1.

 * 1.0.4 (2014-11-20)

     * bug #63 - Password of `null` returns `null` while raising an error
     * bug #64 - Support for process isolation via PHPUnit
     * bug #56 - Minor formatting issues
     * bug #48 - Integers aren't "strings" so exception is thrown
     * PR #69 - Missing `PASSWORD_BCRYPT_DEFAULT_COST` constant definition
     * PR #70 - Fix test suite with Travis
     * PR #58 - Add `PasswordCompat\binary\check()` function to encapsulate tests
