package domain

import (
	"unicode"
	"unicode/utf8"
)

// MinPasswordLength is the password policy floor: 8 characters with one
// uppercase letter and one symbol. Deliberately memorable over maximal:
// the user base skews elderly, so length beyond 8 buys less than a
// second factor (which admins always have).
const MinPasswordLength = 8

// CheckPasswordComplexity enforces the character policy: at least
// MinPasswordLength characters (runes, not bytes), one uppercase letter
// and one symbol (anything that is neither a letter nor a digit).
// History rules live with the caller (usecase/auth), which owns hashes.
func CheckPasswordComplexity(pw string) error {
	if utf8.RuneCountInString(pw) < MinPasswordLength {
		return wrapValidation("password must be at least 8 characters")
	}
	var upper, symbol bool
	for _, r := range pw {
		switch {
		case unicode.IsUpper(r):
			upper = true
		case !unicode.IsLetter(r) && !unicode.IsDigit(r):
			symbol = true
		}
	}
	if !upper {
		return wrapValidation("password must contain an uppercase letter")
	}
	if !symbol {
		return wrapValidation("password must contain a symbol")
	}
	return nil
}
