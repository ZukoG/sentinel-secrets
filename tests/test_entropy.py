from sentinel_secrets.entropy import shannon_entropy, is_high_entropy


def test_empty_string_has_zero_entropy() -> None:
    assert shannon_entropy("") == 0.0


def test_uniform_string_has_zero_entropy() -> None:
    assert shannon_entropy("aaaaaaaaaa") == 0.0


def test_random_secret_has_higher_entropy_than_english() -> None:
    secret = "kJ8x9QeqWM3vLpN2Rt7YbHcZ4FgAsDwU"
    sentence = "This is a normal English sentence with ordinary words."

    assert shannon_entropy(secret) > shannon_entropy(sentence)


def test_high_entropy_returns_true_for_random_secret() -> None:
    secret = "kJ8x9QeqWM3vLpN2Rt7YbHcZ4FgAsDwU"

    assert is_high_entropy(secret) is True


def test_high_entropy_returns_false_for_english_sentence() -> None:
    sentence = (
        "This is a normal English sentence with ordinary words "
        "that people might write."
    )

    assert is_high_entropy(sentence) is False


def test_high_entropy_returns_false_for_short_random_string() -> None:
    short_string = "aB3!xZ9"

    assert is_high_entropy(short_string) is False


def test_high_entropy_respects_custom_min_length() -> None:
    secret = "kJ8x9QeqWM3vLpN2Rt7YbHcZ4FgAsDwU"

    assert is_high_entropy(secret, min_length=100) is False
