"""목록 조회 공통 페이징·정렬 — 인시던트 티켓과 보안 이벤트가 함께 쓴다.

왜 서버가 하나 — 화면(JS)이 100건을 받아 20개씩 잘라 보여줄 수도 있지만,
그러면 ① 101번째부터는 아예 볼 수 없고 ② '총 몇 건·몇 페이지'를 정확히 못 쓴다.
그래서 서버가 `page·per_page·sort·order` 를 받아 그 페이지만 꺼내고 총 건수를 센다.

눈에 잘 안 띄는 함정 두 개를 여기서 한 번에 막는다:

1. **심각도 정렬** — severity 는 글자다. 글자순으로 ORDER BY 하면
   Critical < High < Low < Medium 이 되어 내림차순 1위가 `Medium` 이 된다.
   SQL CASE 로 Critical=4 … Low=1 서열을 매겨 정렬한다.

2. **동률 정렬키** — `created_at` 이 똑같은 행이 여러 개면 DB 는 순서를 보장하지
   않는다(실행 계획에 따라 매 쿼리 달라질 수 있다). 1페이지에서 본 행이
   2페이지에 또 나오고, 어떤 행은 아무 페이지에도 안 나온다. 그래서 항상
   `id` 를 같은 방향 2차 정렬키로 붙여 순서를 고정한다.
"""
from math import ceil

from sqlalchemy import case

DEFAULT_PER_PAGE = 20
MAX_PER_PAGE = 100          # 한 번에 DB 를 통째로 긁어가지 못하게 두는 상한

# 심각도 서열 — 숫자가 클수록 급하다(내림차순에서 위로 온다).
SEVERITY_RANK = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1}


class SortError(ValueError):
    """허용 목록에 없는 sort/order. 라우트가 400 으로 바꿔 돌려준다."""


def severity_rank(column):
    """글자 심각도를 서열 숫자로 바꾸는 SQL 식(정렬용).

    목록에 없는 값(오타·신규 등급)은 0 — 가장 낮게 취급한다.
    """
    return case(SEVERITY_RANK, value=column, else_=0)


def _int_arg(args, name, default):
    """쿼리 파라미터를 정수로. 비었거나 숫자가 아니면 기본값(화면이 깨지지 않게)."""
    try:
        return int(args[name])
    except (KeyError, TypeError, ValueError):
        return default


def paginate(query, args, sort_map, id_column, default_sort='created_at'):
    """필터가 끝난 query 에 정렬·페이징을 걸어 `(rows, meta)` 를 돌려준다.

    Args:
        query:     필터(`filter_by`)까지 적용된 SQLAlchemy 쿼리.
        args:      `request.args` (page·per_page·limit·sort·order 를 읽는다).
        sort_map:  허용 정렬 컬럼 {이름: 컬럼 또는 SQL 식}. **화이트리스트** —
                   여기 없는 이름은 거부하므로 임의 문자열이 ORDER BY 로 가지 않는다.
        id_column: 동률일 때 쓸 2차 정렬키(보통 모델의 `id`).

    Returns:
        (rows, meta) — meta 는 page·per_page·total·total_pages·sort·order.

    Raises:
        SortError: sort 가 화이트리스트 밖이거나 order 가 asc|desc 가 아닐 때.
    """
    sort = (args.get('sort') or default_sort).strip()
    if sort not in sort_map:
        raise SortError(
            f"sort 는 {', '.join(sorted(sort_map))} 중 하나여야 합니다 (받은 값: {sort}).")

    order = (args.get('order') or 'desc').strip().lower()
    if order not in ('asc', 'desc'):
        raise SortError(f"order 는 asc 또는 desc 여야 합니다 (받은 값: {order}).")

    # per_page 가 없으면 예전 화면이 쓰던 limit 을 그대로 받아들인다(호환).
    per_page = _int_arg(args, 'per_page', _int_arg(args, 'limit', DEFAULT_PER_PAGE))
    per_page = max(1, min(per_page, MAX_PER_PAGE))
    page = max(1, _int_arg(args, 'page', 1))      # 0·음수·글자는 1페이지로

    # 총 건수는 **필터가 적용된** 쿼리에서 센다. 전체 건수를 쓰면 필터를 걸었을 때
    # 있지도 않은 페이지 버튼이 생긴다.
    total = query.order_by(None).count()
    total_pages = max(1, ceil(total / per_page))  # 0건이어도 '1 / 1 페이지'

    direction = (lambda c: c.desc()) if order == 'desc' else (lambda c: c.asc())
    rows = (query
            .order_by(direction(sort_map[sort]), direction(id_column))
            .limit(per_page)
            .offset((page - 1) * per_page)
            .all())

    meta = {'page': page, 'per_page': per_page, 'total': total,
            'total_pages': total_pages, 'sort': sort, 'order': order}
    return rows, meta
