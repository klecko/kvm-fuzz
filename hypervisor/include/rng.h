#include <x86intrin.h> // _rdtsc()
#include "common.h"

// Used for mutating inputs. We don't use glibc rand() because it uses locks
// in order to be thread safe. Instead, we implement a simpler algorithm, and
// each thread will have its own rng.
class Rng {
	private:
		uint64_t x_state;
		uint64_t y_state;
		uint64_t z_state;

		inline uint64_t rotl(uint64_t n, unsigned int rot) {
			return (n << rot) | (n >> (8*sizeof(n) - rot));
		}

	public:
		Rng(){
			x_state = _rdtsc();
			y_state = _rdtsc();
			z_state = _rdtsc();
		}

		inline uint64_t rnd(){
			// RomuTrio
			uint64_t xp = x_state, yp = y_state, zp = z_state;
			x_state = 15241094284759029579u * zp;
			y_state = yp - xp;  y_state = rotl(y_state, 12);
			z_state = zp - yp;  z_state = rotl(z_state, 44);
			return xp;
		}

		inline uint64_t rnd(uint64_t min, uint64_t max){
			ASSERT(max >= min, "rnd bad range: %lu, %lu", min, max);
			return min + (rnd() % (max-min+1));
		}

		inline uint64_t rnd_exp(uint64_t min, uint64_t max){
			uint64_t x = rnd(min, max);
			return rnd(min, x);
		}
};