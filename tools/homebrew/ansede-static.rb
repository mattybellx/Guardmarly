# Homebrew formula for ansede-static
# Install with: brew install mattybellx/ansede/ansede-static
#
# Or from a local tap:
#   brew tap mattybellx/ansede
#   brew install ansede-static

class AnsedeStatic < Formula
  include Language::Python::Virtualenv

  desc "Offline SAST scanner — finds 7.5x more than CodeQL. 100% CVE recall, 0.4% FP rate"
  homepage "https://github.com/mattybellx/Ansede"
  url "https://files.pythonhosted.org/packages/source/a/ansede-static/ansede-static-5.2.0.tar.gz"
  sha256 "DE20F07B0E0B87C0D2EB22108A597990F701C11C49C1F7AF346B0531E2DD5859"
  license "MIT"

  livecheck do
    url :stable
    regex(%r{/ansede-static[._-]v?(\d+(?:\.\d+)+)\.t}i)
  end

  depends_on "python@3.12"

  def install
    virtualenv_install_with_resources

    # Also install the `ansede` alias
    bin.install_symlink bin/"ansede-static" => "ansede"
  end

  test do
    # Basic smoke test: scan a minimal Python file
    (testpath/"test.py").write <<~PYTHON
      import sqlite3
      def get_user(user_id):
          conn = sqlite3.connect("db.sqlite3")
          cursor = conn.cursor()
          cursor.execute("SELECT * FROM users WHERE id = " + user_id)
          return cursor.fetchall()
    PYTHON

    output = shell_output("#{bin}/ansede-static test.py --format json 2>&1")
    assert_match "sql_injection", output.downcase

    # Verify version output
    version_output = shell_output("#{bin}/ansede-static --version 2>&1")
    assert_match version.to_s, version_output
  end
end
