from __future__ import annotations

from vulnnote_manager.database import connect_database


def _csrf(client) -> str:
    with client.session_transaction() as state:
        return state["csrf_token"]


def _create_project(client, name: str = "診断案件") -> int:
    client.get("/projects/new")
    response = client.post(
        "/projects/new", data={"csrf_token": _csrf(client), "name": name}, follow_redirects=False
    )
    assert response.status_code == 302
    return int(response.headers["Location"].rstrip("/").split("/")[-1])


def _create_target(client, project_id: int, *, name: str = "Webアプリ") -> int:
    client.get(f"/projects/{project_id}/targets/new")
    response = client.post(
        f"/projects/{project_id}/targets/new",
        data={"csrf_token": _csrf(client), "name": name, "base_url": "https://example.test"},
    )
    assert response.status_code == 302
    return int(response.headers["Location"].rstrip("/").split("/")[-1])


def _create_note(
    client, target_id: int, *, title: str = "XSS", severity: str = "High",
    status: str = "未確認", vulnerability_type: str = "クロスサイトスクリプティング（XSS）",
    discovered_at: str = "2026-07-16T12:00",
) -> int:
    client.get(f"/targets/{target_id}/notes/new")
    response = client.post(
        f"/targets/{target_id}/notes/new",
        data={
            "csrf_token": _csrf(client), "title": title, "severity": severity, "status": status,
            "vulnerability_type": vulnerability_type,
            "discovered_at": discovered_at, "timezone_offset": "-540",
            "evidence": "GET /?q=<script>alert(1)</script>",
        },
    )
    assert response.status_code == 302
    return int(response.headers["Location"].rstrip("/").split("/")[-1])


def test_project_crud_validation_and_conflict(client, settings) -> None:
    client.get("/projects/new")
    invalid = client.post("/projects/new", data={"csrf_token": _csrf(client), "name": "   "})
    assert invalid.status_code == 422
    assert "空白以外の文字" in invalid.get_data(as_text=True)

    project_id = _create_project(client)
    detail = client.get(f"/projects/{project_id}")
    assert "診断案件" in detail.get_data(as_text=True)

    db = connect_database(settings.database_path)
    try:
        current = db.execute("SELECT updated_at FROM projects WHERE id=?", (project_id,)).fetchone()[0]
    finally:
        db.close()
    client.get(f"/projects/{project_id}/edit")
    updated = client.post(
        f"/projects/{project_id}/edit",
        data={"csrf_token": _csrf(client), "name": "更新案件", "updated_at": current},
    )
    assert updated.status_code == 302
    conflict = client.post(
        f"/projects/{project_id}/edit",
        data={"csrf_token": _csrf(client), "name": "古い更新", "updated_at": current},
    )
    assert conflict.status_code == 409
    assert "最新の内容" in conflict.get_data(as_text=True)


def test_validation_messages_are_associated_with_form_controls(client) -> None:
    client.get("/projects/new")
    project = client.post(
        "/projects/new", data={"csrf_token": _csrf(client), "name": " "}
    ).get_data(as_text=True)
    assert 'id="name" name="name"' in project
    assert 'aria-invalid="true" aria-describedby="name-error"' in project
    assert 'id="name-error" class="field-error"' in project

    project_id = _create_project(client)
    client.get(f"/projects/{project_id}/targets/new")
    target = client.post(
        f"/projects/{project_id}/targets/new",
        data={"csrf_token": _csrf(client), "name": " ", "base_url": "not-a-url"},
    ).get_data(as_text=True)
    assert 'aria-invalid="true" aria-describedby="name-error"' in target
    assert 'aria-describedby="base_url-warning"' in target
    assert 'id="base_url-warning" class="field-warning"' in target

    target_id = _create_target(client, project_id)
    client.get(f"/targets/{target_id}/notes/new")
    note = client.post(
        f"/targets/{target_id}/notes/new",
        data={
            "csrf_token": _csrf(client),
            "title": " ",
            "severity": "invalid",
            "status": "invalid",
            "discovered_at": "",
            "timezone_offset": "0",
            "target_url": "not-a-url",
        },
    ).get_data(as_text=True)
    for field in ("title", "severity", "status"):
        assert f'aria-invalid="true" aria-describedby="{field}-error"' in note
        assert f'id="{field}-error" class="field-error"' in note
    assert note.count('aria-invalid="true" aria-describedby="discovered_at-error"') == 3
    assert 'id="discovered_at-error" class="field-error"' in note
    assert 'aria-describedby="target_url-warning"' in note


def test_note_form_uses_firefox_compatible_date_hour_and_minute_inputs(client) -> None:
    project_id = _create_project(client)
    target_id = _create_target(client, project_id)

    form = client.get(f"/targets/{target_id}/notes/new").get_data(as_text=True)

    assert 'type="date" id="discovered_date" name="discovered_date"' in form
    assert 'id="discovered_hour" name="discovered_hour"' in form
    assert 'id="discovered_minute" name="discovered_minute"' in form
    assert 'type="time"' not in form
    assert 'type="datetime-local"' not in form

    created = client.post(
        f"/targets/{target_id}/notes/new",
        data={
            "csrf_token": _csrf(client),
            "title": "Firefox日時入力確認",
            "severity": "High",
            "status": "未確認",
            "discovered_date": "2026-07-20",
            "discovered_hour": "14",
            "discovered_minute": "35",
            "timezone_offset": "-540",
        },
        follow_redirects=False,
    )
    assert created.status_code == 302


def test_three_level_crud_and_html_is_escaped(client) -> None:
    project_id = _create_project(client)
    target_id = _create_target(client, project_id)
    note_id = _create_note(client, target_id, title="<script>alert('title')</script>")

    target_detail = client.get(f"/targets/{target_id}").get_data(as_text=True)
    assert "Webアプリ" in target_detail
    note_detail = client.get(f"/notes/{note_id}").get_data(as_text=True)
    assert "<script>alert" not in note_detail
    assert "&lt;script&gt;alert" in note_detail
    assert "GET /?q=&lt;script&gt;alert(1)&lt;/script&gt;" in note_detail


def test_unknown_parent_ids_are_rejected(client) -> None:
    assert client.get("/projects/999/targets/new").status_code == 404
    assert client.get("/targets/999/notes/new").status_code == 404


def test_invalid_url_is_saved_with_visible_warning(client) -> None:
    project_id = _create_project(client)
    client.get(f"/projects/{project_id}/targets/new")
    response = client.post(
        f"/projects/{project_id}/targets/new",
        data={"csrf_token": _csrf(client), "name": "警告対象", "base_url": "not-a-url"},
        follow_redirects=True,
    )
    body = response.get_data(as_text=True)
    assert response.status_code == 200
    assert "完全なURLではありません" in body
    assert "not-a-url" in body


def test_new_note_defaults_to_unconfirmed(client) -> None:
    target_id = _create_target(client, _create_project(client))
    page = client.get(f"/targets/{target_id}/notes/new").get_data(as_text=True)
    assert '<option value="未確認" selected>' in page


def test_project_list_search_sort_pagination_and_invalid_query(client, app) -> None:
    app.config["PAGE_SIZE"] = 2
    for name in ("Gamma", "Alpha", "Beta"):
        _create_project(client, name)

    first = client.get("/projects?sort=name&direction=asc").get_data(as_text=True)
    assert first.index("Alpha") < first.index("Beta")
    assert "3件中 1〜2件" in first
    assert "page=2&amp;sort=name&amp;direction=asc" in first

    filtered = client.get("/projects?q=Gamma").get_data(as_text=True)
    assert "Gamma" in filtered
    assert "Alpha" not in filtered
    no_match = client.get("/projects?q=存在しない").get_data(as_text=True)
    assert "条件に一致する案件はありません" in no_match
    assert client.get("/projects?sort=name%20DESC").status_code == 400
    assert client.get("/projects?page=0").status_code == 400


def test_target_list_combines_search_project_filter_and_sort(client) -> None:
    project_a = _create_project(client, "A案件")
    project_b = _create_project(client, "B案件")
    _create_target(client, project_a, name="管理画面")
    _create_target(client, project_b, name="公開画面")

    response = client.get(
        f"/targets?project_id={project_a}&q=管理&sort=name&direction=asc"
    )
    body = response.get_data(as_text=True)
    assert response.status_code == 200
    assert "管理画面" in body
    assert "公開画面" not in body
    assert client.get("/targets?project_id=1%20OR%201=1").status_code == 400


def test_note_list_combines_all_filters_and_uses_semantic_sort(client) -> None:
    project_id = _create_project(client, "検索案件")
    target_id = _create_target(client, project_id, name="検索対象")
    _create_note(
        client, target_id, title="低リスク", severity="Low", status="修正済み",
        vulnerability_type="情報漏えい",
    )
    _create_note(
        client, target_id, title="重大XSS", severity="Critical", status="未確認",
        vulnerability_type="クロスサイトスクリプティング（XSS）",
    )

    filtered = client.get(
        f"/notes?project_id={project_id}&target_id={target_id}&q=script"
        "&severity=Critical&status=未確認&locked=0"
        "&vulnerability_type=クロスサイトスクリプティング（XSS）"
    ).get_data(as_text=True)
    assert "重大XSS" in filtered
    assert "低リスク" not in filtered

    ordered = client.get("/notes?sort=severity&direction=asc").get_data(as_text=True)
    assert ordered.index("重大XSS") < ordered.index("低リスク")
    assert client.get("/notes?severity=Unknown").status_code == 400
    assert client.get("/notes?direction=sideways").status_code == 400


def test_every_note_sort_supports_ascending_and_descending(client) -> None:
    target_id = _create_target(client, _create_project(client, "並べ替え案件"))
    _create_note(
        client, target_id, title="Alpha", severity="Critical", status="未確認",
        vulnerability_type="A種類", discovered_at="2026-07-15T12:00",
    )
    _create_note(
        client, target_id, title="Beta", severity="Low", status="修正済み",
        vulnerability_type="Z種類", discovered_at="2026-07-17T12:00",
    )
    for sort in ("title", "severity", "vulnerability_type", "discovered_at", "status", "created_at", "updated_at"):
        ascending = client.get(f"/notes?sort={sort}&direction=asc").get_data(as_text=True)
        descending = client.get(f"/notes?sort={sort}&direction=desc").get_data(as_text=True)
        assert ascending.index("Alpha") < ascending.index("Beta"), sort
        assert descending.index("Beta") < descending.index("Alpha"), sort


def test_target_and_note_show_all_system_fields_and_note_conflict(client, settings) -> None:
    target_id = _create_target(client, _create_project(client))
    target_body = client.get(f"/targets/{target_id}").get_data(as_text=True)
    assert "作成日時" in target_body
    assert "更新日時" in target_body

    note_id = _create_note(client, target_id)
    db = connect_database(settings.database_path)
    try:
        current = db.execute(
            "SELECT updated_at FROM vulnerability_notes WHERE id = ?", (note_id,)
        ).fetchone()[0]
    finally:
        db.close()
    payload = {
        "csrf_token": _csrf(client), "title": "更新後", "severity": "Medium",
        "status": "確認済み", "discovered_at": "2026-07-16T13:00",
        "timezone_offset": "-540", "updated_at": current,
    }
    assert client.post(f"/notes/{note_id}/edit", data=payload).status_code == 302
    assert client.post(f"/notes/{note_id}/edit", data=payload).status_code == 409
    detail = client.get(f"/notes/{note_id}").get_data(as_text=True)
    assert "更新後" in detail
    assert "Medium" in detail
    assert "確認済み" in detail


def test_export_responses_have_safe_download_headers_and_unicode_content(client) -> None:
    project_id = _create_project(client, "日本語案件")
    target_id = _create_target(client, project_id, name="Unicode対象")
    note_id = _create_note(client, target_id, title="改行\r\nを含むメモ")

    csv_response = client.get(f"/notes/{note_id}/exports/csv")
    assert csv_response.status_code == 200
    assert csv_response.mimetype == "text/csv"
    assert csv_response.headers["Content-Disposition"] == f"attachment; filename=note-{note_id}.csv"
    assert csv_response.data.startswith(b"\xef\xbb\xbf")
    assert "日本語案件" in csv_response.data.decode("utf-8-sig")

    markdown_response = client.get(f"/projects/{project_id}/exports/markdown")
    assert markdown_response.status_code == 200
    assert markdown_response.mimetype == "text/markdown"
    assert markdown_response.headers["Content-Disposition"] == (
        f"attachment; filename=project-{project_id}.md"
    )
    markdown = markdown_response.data.decode("utf-8")
    assert "日本語案件" in markdown
    assert "Unicode対象" in markdown
