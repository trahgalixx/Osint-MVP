import hashlib

import pytest

from footprint_audit import (
    Response,
    count_in_range_response,
    evaluate,
    load_sites,
    parse_args,
    sha1_prefix_suffix,
)


def resp(status=200, text="", final_url="https://example.com/x"):
    return Response(status, text, final_url)


def test_sha1_prefix_suffix_splits_hash():
    full = hashlib.sha1(b"password").hexdigest().upper()
    prefix, suffix = sha1_prefix_suffix("password")
    assert prefix + suffix == full
    assert len(prefix) == 5


def test_count_in_range_response_found_and_missing():
    body = "AAAAA:3\r\nBBBBB:42\r\nCCCCC:0"
    assert count_in_range_response(body, "BBBBB") == 42
    assert count_in_range_response(body, "ZZZZZ") == 0


@pytest.mark.parametrize("check, response, expected", [
    ({"type": "status"}, resp(200), "found"),
    ({"type": "status"}, resp(404), "not_found"),
    ({"type": "status"}, resp(410), "not_found"),
    ({"type": "status"}, resp(403), "error"),
    ({"type": "present", "marker": "OK"}, resp(200, "..OK.."), "found"),
    ({"type": "present", "marker": "OK"}, resp(200, "nope"), "not_found"),
    ({"type": "absent", "marker": "not found"}, resp(200, "user not found"), "not_found"),
    ({"type": "absent", "marker": "not found"}, resp(200, "profil"), "found"),
    ({"type": "redirect", "marker": "/404"}, resp(200, final_url="https://a.com/404"), "not_found"),
    ({"type": "redirect", "marker": "/404"}, resp(200, final_url="https://a.com/me"), "found"),
    ({"type": "json_nonempty"}, resp(200, '[{"id": 1}]'), "found"),
    ({"type": "json_nonempty"}, resp(200, "[]"), "not_found"),
    ({"type": "json_nonempty"}, resp(200, "<html>"), "error"),
])
def test_evaluate(check, response, expected):
    assert evaluate(check, response) == expected


def test_sites_json_is_valid():
    sites = load_sites()
    names = [s["name"] for s in sites]
    assert len(names) == len(set(names)), "nama situs duplikat"
    for s in sites:
        assert "{u}" in s["url"]
        assert s["check"]["type"] in {"status", "present", "absent", "redirect",
                                      "json_nonempty", "manual"}


def test_parse_args_requires_input():
    with pytest.raises(SystemExit):
        parse_args([])


def test_parse_args_rejects_bad_username():
    with pytest.raises(SystemExit):
        parse_args(["-u", "../etc/passwd"])


def test_parse_args_username():
    args = parse_args(["-u", "octocat"])
    assert args.username == "octocat"
