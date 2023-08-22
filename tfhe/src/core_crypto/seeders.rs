//! This module contains methods to get a random seed.
//!
//! Seeding depends on the underlying OS/hardware. Here, many strategies are proposed to (securely)
//! obtain a seed. A random seed is useful to have compressed keys and is used as a prerequisite
//! for cryptographically secure pseudo random number generators.

pub use crate::core_crypto::commons::math::random::Seeder;
#[cfg(all(target_os = "macos", not(feature = "__wasm_api")))]
pub use concrete_csprng::seeders::AppleSecureEnclaveSeeder;
#[cfg(feature = "seeder_x86_64_rdseed")]
pub use concrete_csprng::seeders::RdseedSeeder;
#[cfg(feature = "seeder_unix")]
pub use concrete_csprng::seeders::UnixSeeder;

#[cfg(feature = "custom-seeder")]
use crate::core_crypto::seeders::custom_seeder::{CUSTOM_SEEDER_INSTANCE, CustomSeeder};

#[cfg(feature = "custom-seeder")]
pub mod custom_seeder {
    use std::sync::Mutex;
    use crate::core_crypto::commons::math::random::{Seed, Seeder};
    use lazy_static::lazy_static;
    use rand_core::{RngCore, SeedableRng};
    use rand_chacha::ChaChaRng;
    use sha2::Digest;

    pub fn set_custom_seeder(seed: String) {
        CUSTOM_SEEDER_INSTANCE.lock().unwrap().set_seed(seed)
    }

    #[derive(Clone)]
    pub struct CustomSeeder {
        context: Option<String>,
    }

    lazy_static! {
        pub static ref CUSTOM_SEEDER_INSTANCE: Mutex<CustomSeeder> = Mutex::new(CustomSeeder {
            context: None
        });
    }

    impl CustomSeeder {
        // A new function to initialize the CustomSeeder with an external context
        pub fn new(context: Option<String>) -> Self {
            CustomSeeder { context }
        }

        pub fn set_seed(&mut self, seed: String) {
            self.context = Some(seed);
        }
    }

    impl Seeder for CustomSeeder {

        fn seed(&mut self) -> Seed {
            // Generate a seed using the external context or some other logic
            // This is a dummy implementation, you can customize it as per your needs
            let mut hasher = sha2::Sha256::new();
            // Assuming the context is a string, convert it into bytes and get a seed.
            // If context is None, using a default value
            let binding = "some-default-string-that-is-long".to_string();
            let context_bytes = self.context.as_ref().unwrap_or(&binding).as_bytes();
            let mut buffer = [0u8; 32];

            // write input message
            hasher.update(context_bytes);
            let hash = hasher.finalize();
            buffer.copy_from_slice(hash.as_slice());


            let mut rng: ChaChaRng = ChaChaRng::from_seed(buffer);

            let mut seed_bytes = [0u8; 16];
            rng.fill_bytes(&mut seed_bytes);

            Seed(u128::from_le_bytes(seed_bytes))
        }

        fn is_available() -> bool
            where
                Self: Sized,
        {
            // You can check the availability based on the context or some other criteria
            // For this example, I'm assuming it's always available
            true
        }
    }
}


#[cfg(feature = "__wasm_api")]
mod wasm_seeder {
    use crate::core_crypto::commons::math::random::{Seed, Seeder};
    // This is used for web interfaces
    use getrandom::getrandom;

    pub(super) struct WasmSeeder {}

    impl Seeder for WasmSeeder {
        fn seed(&mut self) -> Seed {
            let mut buffer = [0u8; 16];
            getrandom(&mut buffer).unwrap();

            Seed(u128::from_le_bytes(buffer))
        }

        fn is_available() -> bool
        where
            Self: Sized,
        {
            true
        }
    }
}

/// Return an available boxed [`Seeder`] prioritizing hardware entropy sources.
///
/// # Note
///
/// With the `seeder_x86_64_rdseed` feature enabled on `x86_64` CPUs the rdseed seeder is
/// prioritized.
///
/// On macOS the next seeder to be prioritized uses Apple's [`Randomization
/// Service`](`https://developer.apple.com/documentation/security/randomization_services?language=objc`)
/// calling [`SecRandomCopyBytes`](`https://developer.apple.com/documentation/security/1399291-secrandomcopybytes?language=objc`).
///
/// With the `seeder_unix` feature enabled on Unix platforms, `/dev/random` is used as a fallback
/// and the quality of the generated seeds depends on the particular implementation of the platform
/// your code is running on.
///
/// For the wasm32 target the [`getrandom`](`https://docs.rs/getrandom/latest/getrandom/`)
/// js random number generator is used as a source of
/// [`cryptographically random numbers per the W3C documentation`](`https://www.w3.org/TR/WebCryptoAPI/#Crypto-method-getRandomValues`).
///
/// # Example
///
/// ```
/// use tfhe::core_crypto::prelude::*;
///
/// let mut seeder = new_seeder();
/// let mut seeder = seeder.as_mut();
///
/// let mut first_seed = seeder.seed();
/// let mut second_seed = seeder.seed();
/// assert_ne!(first_seed, second_seed);
/// ```
pub fn new_seeder() -> Box<dyn Seeder> {
    let mut seeder: Option<Box<dyn Seeder>> = None;

    let err_msg;

    #[cfg(not(feature = "__wasm_api"))]
    {
        #[cfg(feature = "custom-seeder")]
        {
            if CustomSeeder::is_available() {
                seeder = Some(Box::new((*CUSTOM_SEEDER_INSTANCE).lock().unwrap().clone()))
            }
        }
        #[cfg(feature = "seeder_x86_64_rdseed")]
        {
            if RdseedSeeder::is_available() {
                seeder = Some(Box::new(RdseedSeeder));
            }
        }

        // This Seeder is normally always available on macOS, so we enable it by default when on
        // that platform
        #[cfg(target_os = "macos")]
        {
            if seeder.is_none() && AppleSecureEnclaveSeeder::is_available() {
                seeder = Some(Box::new(AppleSecureEnclaveSeeder))
            }
        }

        #[cfg(feature = "seeder_unix")]
        {
            if seeder.is_none() && UnixSeeder::is_available() {
                seeder = Some(Box::new(UnixSeeder::new(0)));
            }
        }

        #[cfg(not(feature = "__c_api"))]
        {
            err_msg = "Unable to instantiate a seeder, make sure to enable a seeder feature \
    like seeder_unix for example on unix platforms.";
        }

        #[cfg(feature = "__c_api")]
        {
            err_msg = "No compatible seeder for current machine found.";
        }
    }

    #[cfg(feature = "__wasm_api")]
    {
        if seeder.is_none() && wasm_seeder::WasmSeeder::is_available() {
            seeder = Some(Box::new(wasm_seeder::WasmSeeder {}))
        }

        err_msg = "No compatible seeder found. Consider changing browser or dev environment";
    }

    seeder.expect(err_msg)
}
