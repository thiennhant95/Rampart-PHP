<?php

declare(strict_types=1);

namespace Rampart\Php\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Rampart\Php\Analyzers\Security\DangerousFunctionAnalyzer;
use Rampart\Php\Analyzers\Security\DebugOutputAnalyzer;
use Rampart\Php\Analyzers\Security\HeaderInjectionAnalyzer;
use Rampart\Php\Analyzers\Security\InsecureRandomAnalyzer;
use Rampart\Php\Analyzers\Security\InsecureSessionAnalyzer;
use Rampart\Php\Analyzers\Security\LdapInjectionAnalyzer;
use Rampart\Php\Analyzers\Security\SqlInjectionAnalyzer;
use Rampart\Php\Analyzers\Security\WeakCryptoAnalyzer;
use Rampart\Php\Analyzers\Security\XssEchoAnalyzer;

/**
 * Pins the plain-PHP rules added on top of the Laravel corpus: each test is a
 * true positive next to the nearest false positive, so a future heuristic
 * change cannot quietly widen or narrow the rule.
 */
final class GenericSecurityAnalyzersTest extends TestCase
{
    /**
     * @param array<string, string> $files
     * @return list<string>
     */
    private function rules(object $analyzer, array $files): array
    {
        $dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'rampart-generic-' . uniqid('', true);
        $paths = [];
        foreach ($files as $relative => $code) {
            $path = $dir . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $relative);
            @mkdir(dirname($path), 0777, true);
            file_put_contents($path, $code);
            $paths[] = $path;
        }

        $rules = [];
        foreach ($analyzer->analyze($paths) as $issue) {
            $rules[] = $issue->rule;
        }

        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::CHILD_FIRST
        );
        foreach ($iterator as $item) {
            $item->isDir() ? @rmdir($item->getPathname()) : @unlink($item->getPathname());
        }
        @rmdir($dir);

        return $rules;
    }

    public function testEchoOfRequestInputIsXss(): void
    {
        $rules = $this->rules(new XssEchoAnalyzer(), [
            'src/view.php' => "<?php\necho \$_GET['name'];\n",
        ]);

        self::assertContains('XSS_ECHO', $rules);
    }

    public function testEchoOfLocalVariableIsNotXss(): void
    {
        $rules = $this->rules(new XssEchoAnalyzer(), [
            'src/view.php' => "<?php\n\$title = 'Hello';\necho \$title;\n",
        ]);

        self::assertNotContains('XSS_ECHO', $rules);
    }

    public function testEscapedRequestEchoIsNotXss(): void
    {
        $rules = $this->rules(new XssEchoAnalyzer(), [
            'src/view.php' => "<?php\necho esc(\$_GET['name']);\necho htmlspecialchars(\$_GET['q'], ENT_QUOTES, 'UTF-8');\n",
        ]);

        self::assertNotContains('XSS_ECHO', $rules);
    }

    public function testBooleanRequestPredicateIsNotXss(): void
    {
        $rules = $this->rules(new XssEchoAnalyzer(), [
            'src/view.php' => "<?php\necho \$request->isAJAX() ? 'yes' : 'no';\n",
        ]);

        self::assertNotContains('XSS_ECHO', $rules);
    }

    public function testPdoConcatWithRequestInputIsSqlInjection(): void
    {
        $rules = $this->rules(new SqlInjectionAnalyzer(), [
            'src/Repo.php' => "<?php\n\$q = \$_GET['q'];\n\$pdo->query('SELECT * FROM users WHERE name = ' . \$q);\n",
        ]);

        self::assertContains('SQL_INJECTION', $rules);
    }

    public function testPdoLiteralQueryIsNotSqlInjection(): void
    {
        $rules = $this->rules(new SqlInjectionAnalyzer(), [
            'src/Repo.php' => "<?php\n\$pdo->query('SELECT * FROM users');\n",
        ]);

        self::assertNotContains('SQL_INJECTION', $rules);
    }

    public function testExtractIsDangerous(): void
    {
        $rules = $this->rules(new DangerousFunctionAnalyzer(), [
            'src/Boot.php' => "<?php\nextract(\$_POST);\n",
        ]);

        self::assertContains('DANGEROUS_FUNCTION', $rules);
    }

    public function testPregReplaceEvalModifierIsDangerous(): void
    {
        $rules = $this->rules(new DangerousFunctionAnalyzer(), [
            'src/Tpl.php' => "<?php\npreg_replace('/x/e', \$_GET['code'], 'x');\n",
        ]);

        self::assertContains('DANGEROUS_FUNCTION', $rules);
    }

    public function testTaintedHeaderIsReported(): void
    {
        $rules = $this->rules(new HeaderInjectionAnalyzer(), [
            'src/Http.php' => "<?php\nheader('X-Name: ' . \$_GET['name']);\n",
        ]);

        self::assertContains('HEADER_INJECTION', $rules);
    }

    public function testLiteralHeaderIsNotReported(): void
    {
        $rules = $this->rules(new HeaderInjectionAnalyzer(), [
            'src/Http.php' => "<?php\nheader('X-Frame-Options: DENY');\n",
        ]);

        self::assertNotContains('HEADER_INJECTION', $rules);
    }

    public function testTaintedLdapFilterIsReported(): void
    {
        $rules = $this->rules(new LdapInjectionAnalyzer(), [
            'src/Ldap.php' => "<?php\nldap_search(\$link, 'dc=example,dc=com', '(uid=' . \$_GET['uid'] . ')');\n",
        ]);

        self::assertContains('LDAP_INJECTION', $rules);
    }

    public function testWeakCipherIsReportedButAesGcmIsNot(): void
    {
        $weak = $this->rules(new WeakCryptoAnalyzer(), [
            'src/Crypto.php' => "<?php\nopenssl_encrypt(\$data, 'des-ecb', \$key);\n",
        ]);
        $strong = $this->rules(new WeakCryptoAnalyzer(), [
            'src/Crypto.php' => "<?php\nopenssl_encrypt(\$data, 'aes-256-gcm', \$key);\n",
        ]);

        self::assertContains('WEAK_CRYPTO', $weak);
        self::assertNotContains('WEAK_CRYPTO', $strong);
    }

    public function testDisabledSessionFlagsAreReported(): void
    {
        $rules = $this->rules(new InsecureSessionAnalyzer(), [
            'src/Session.php' => "<?php\nini_set('session.cookie_httponly', '0');\n",
        ]);

        self::assertContains('INSECURE_SESSION', $rules);
    }

    public function testSecureSessionFlagsAreNotReported(): void
    {
        $rules = $this->rules(new InsecureSessionAnalyzer(), [
            'src/Session.php' => "<?php\nini_set('session.cookie_httponly', '1');\n",
        ]);

        self::assertNotContains('INSECURE_SESSION', $rules);
    }

    public function testLcgValueForTokenIsReported(): void
    {
        $rules = $this->rules(new InsecureRandomAnalyzer(), [
            'src/Token.php' => "<?php\n\$token = lcg_value();\n",
        ]);

        self::assertContains('INSECURE_RANDOM', $rules);
    }

    public function testLcgValueWithoutSecurityContextIsNotReported(): void
    {
        $rules = $this->rules(new InsecureRandomAnalyzer(), [
            'src/Noise.php' => "<?php\n\$noise = lcg_value();\n",
        ]);

        self::assertNotContains('INSECURE_RANDOM', $rules);
    }

    public function testDebugOutputIsReportedInAppCode(): void
    {
        $rules = $this->rules(new DebugOutputAnalyzer(), [
            'src/Debug.php' => "<?php\nvar_dump(\$data);\n",
        ]);

        self::assertContains('DEBUG_OUTPUT', $rules);
    }

    public function testDebugOutputInTestsIsIgnored(): void
    {
        $rules = $this->rules(new DebugOutputAnalyzer(), [
            'tests/Unit/DebugTest.php' => "<?php\nvar_dump(\$data);\n",
        ]);

        self::assertNotContains('DEBUG_OUTPUT', $rules);
    }
}
