<?php

declare(strict_types=1);

namespace Rampart\Php\Analyzers\Security;

use PhpParser\Node;
use PhpParser\Node\Expr;
use Rampart\Php\Analyzers\AbstractAnalyzer;
use Rampart\Php\Result\Confidence;
use Rampart\Php\Result\Issue;
use Rampart\Php\Result\Severity;

/**
 * Weak / obsolete cryptographic ciphers.
 *
 * Covers OpenSSL and the removed mcrypt extension: DES/3DES, RC2/RC4,
 * Blowfish variants and ECB mode (which hides plaintext structure). Only
 * literal cipher names are checked; a value from config is left to human
 * review rather than guessed.
 */
final class WeakCryptoAnalyzer extends AbstractAnalyzer
{
    private const RULE = 'WEAK_CRYPTO';

    private const CIPHER_ARG = [
        'openssl_encrypt' => 1,
        'openssl_decrypt' => 1,
        'mcrypt_encrypt' => 0,
        'mcrypt_decrypt' => 0,
    ];

    /** @var list<string> */
    private const WEAK_NEEDLES = ['des', 'rc2', 'rc4', 'bf-', 'blowfish', '-ecb', 'ecb'];

    public function analyze(array $files): array
    {
        $issues = [];
        foreach ($files as $file) {
            if (!$this->supports($file) || $this->isTestPath($file)) {
                continue;
            }
            $ast = $this->sharedAst($file);
            if ($ast === null) {
                continue;
            }
            foreach ($this->finder()->findInstanceOf($ast, Expr\FuncCall::class) as $call) {
                if (!$call instanceof Expr\FuncCall || !$call->name instanceof Node\Name) {
                    continue;
                }
                $name = strtolower($call->name->getLast());
                $position = self::CIPHER_ARG[$name] ?? null;
                if ($position === null) {
                    continue;
                }
                $argument = $call->args[$position]->value ?? null;
                if (!$argument instanceof Node\Scalar\String_) {
                    continue;
                }
                $cipher = strtolower($argument->value);
                if (!$this->isWeak($cipher)) {
                    continue;
                }
                $issues[] = $this->makeIssue(
                    self::RULE,
                    sprintf(
                        'Weak cipher "%s" in %s(). Use AES-256-GCM (openssl) or libsodium secretbox.',
                        $argument->value,
                        $name
                    ),
                    $file,
                    $call->getStartLine(),
                    Severity::$Warning,
                    ['function' => $name, 'cipher' => $argument->value],
                    Confidence::$High
                );
            }
        }

        return $issues;
    }

    private function isWeak(string $cipher): bool
    {
        foreach (self::WEAK_NEEDLES as $needle) {
            if (strpos($cipher, $needle) !== false) {
                return true;
            }
        }

        return false;
    }
}
