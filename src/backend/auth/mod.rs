//! # The Auth Module
//!
//! The authentication module has two parts [`check`] and [`security_scheme`].
//!
//! ### [`security_scheme`]
//!
//! This module is the poem security scheme and it's required components. However it doesn't
//! include any checks with the database. It serialises the user data into a user token with a
//! secret hash and deseriles out.
//!
//! ### [`check`]
//!
//! This module checks the client agianst the database and can preform operations aginst it.

pub mod check;
pub mod otp_codes;
pub mod security_scheme;
