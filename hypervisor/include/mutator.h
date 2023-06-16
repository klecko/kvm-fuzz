#include <string>
#include <vector>
#include "rng.h"

class Mutator {
public:
	static const int MIN_MUTATIONS = 1;
	static const int MAX_MUTATIONS = 10;
	typedef void (Mutator::*mutation_strat_t)(std::string& input, Rng& rng);
	static const std::vector<mutation_strat_t> mut_strats;
	static const std::vector<mutation_strat_t> mut_strats_reduce;

	Mutator(const std::vector<std::string>& corpus);
	size_t max_input_size() const;
	void set_max_input_size(size_t size);
	void mutate_input(std::string& input, Rng& rng, bool minimize);

private:
	const std::vector<std::string>& m_corpus;

	// Max input size, used in expand mutation
	size_t m_max_input_size;

	void mut_shrink(std::string& input, Rng& rng);
	void mut_expand(std::string& input, Rng& rng);
	void mut_bit(std::string& input, Rng& rng);
	void mut_dec_byte(std::string& input, Rng& rng);
	void mut_inc_byte(std::string& input, Rng& rng);
	void mut_neg_byte(std::string& input, Rng& rng);
	void mut_add_sub(std::string& input, Rng& rng);
	void mut_set(std::string& input, Rng& rng);
	void mut_swap(std::string& input, Rng& rng);
	void mut_copy(std::string& input, Rng& rng);
	void mut_inter_splice(std::string& input, Rng& rng);
	void mut_insert_rand(std::string& input, Rng& rng);
	void mut_overwrite_rand(std::string& input, Rng& rng);
	void mut_byte_repeat_overwrite(std::string& input, Rng& rng);
	void mut_byte_repeat_insert(std::string& input, Rng& rng);
	void mut_magic_overwrite(std::string& input, Rng& rng);
	void mut_magic_insert(std::string& input, Rng& rng);
	void mut_random_overwrite(std::string& input, Rng& rng);
	void mut_random_insert(std::string& input, Rng& rng);
	void mut_splice_overwrite(std::string& input, Rng& rng);
	void mut_splice_insert(std::string& input, Rng& rng);
};