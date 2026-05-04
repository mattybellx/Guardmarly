from __future__ import annotations

from ansede_static._types import Finding, Severity
from ansede_static.engine.triage import CWETriageRules


def _finding(cwe: str, title: str = "finding") -> Finding:
    return Finding(
        category="security",
        severity=Severity.HIGH,
        title=title,
        description="",
        line=1,
        suggestion="",
        cwe=cwe,
        rule_id="TEST-001",
        agent="tests",
    )


class TestFrameworkSafePatternsInTriage:
    def test_cwe_862_django_login_required_mixin_is_suppressed(self):
        snippet = """
class AdminView(LoginRequiredMixin, View):
    def get(self, request):
        return HttpResponse('ok')
"""
        res = CWETriageRules.triage_cwe_862(_finding("CWE-862"), snippet, "app/views.py")
        assert res is not None
        assert not res.is_true_positive

    def test_cwe_862_fastapi_depends_get_current_user_is_suppressed(self):
        snippet = """
@app.get('/admin/users')
async def list_users(current_user=Depends(get_current_user)):
    return []
"""
        res = CWETriageRules.triage_cwe_862(_finding("CWE-862"), snippet, "api.py")
        assert res is not None
        assert not res.is_true_positive

    def test_cwe_862_nestjs_useguards_is_suppressed(self):
        snippet = """
@Controller('users')
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles('admin')
@Get(':id')
findOne(@Param('id') id: string) {
  return this.usersService.findOne(id);
}
"""
        res = CWETriageRules.triage_cwe_862(_finding("CWE-862"), snippet, "users.controller.ts")
        assert res is not None
        assert not res.is_true_positive


class TestIDORSafePatternsInTriage:
    def test_cwe_639_owner_scoped_filter_is_suppressed(self):
        snippet = """
post = Post.query.filter_by(id=post_id, owner_id=current_user.id).first()
"""
        res = CWETriageRules.triage_cwe_639(_finding("CWE-639"), snippet, "views.py")
        assert res is not None
        assert not res.is_true_positive

    def test_cwe_639_explicit_owner_guard_is_suppressed(self):
        snippet = """
post = Post.query.get(post_id)
if post.owner_id != g.user_id:
    abort(403)
"""
        res = CWETriageRules.triage_cwe_639(_finding("CWE-639"), snippet, "views.py")
        assert res is not None
        assert not res.is_true_positive

    def test_cwe_639_without_owner_scope_not_auto_suppressed(self):
        snippet = """
post = Post.query.get(post_id)
return post
"""
        res = CWETriageRules.triage_cwe_639(_finding("CWE-639"), snippet, "views.py")
        assert res is None
