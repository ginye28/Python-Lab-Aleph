"""터미널에서 돌아가는 자판기.

- 현금 투입 -> 상품 선택 -> 거스름돈 반환
- 거스름돈은 자판기가 실제로 보유한 화폐 재고 안에서만 만들어 준다
- 관리자 모드에서 재고 충전 / 수금

실행: python vending_machine.py
"""

import unicodedata
from dataclasses import dataclass, field

# 큰 단위부터. 자판기가 취급하는 화폐만.
DENOMINATIONS = [10000, 5000, 1000, 500, 100]


def won(amount: int) -> str:
    return f"{amount:,}원"


def pad(text: str, width: int) -> str:
    """한글처럼 두 칸을 차지하는 글자를 감안해 오른쪽을 공백으로 채운다."""
    shown = sum(2 if unicodedata.east_asian_width(ch) in "WF" else 1 for ch in text)
    return text + " " * max(0, width - shown)


def format_plan(plan: dict[int, int]) -> str:
    parts = [f"{won(d)} {n}개" for d, n in sorted(plan.items(), reverse=True) if n]
    return ", ".join(parts) if parts else "없음"


@dataclass
class Product:
    code: str
    name: str
    price: int
    stock: int

    @property
    def sold_out(self) -> bool:
        return self.stock <= 0


@dataclass
class CashBox:
    """자판기가 보유한 화폐. {단위: 개수}"""

    coins: dict[int, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for d in DENOMINATIONS:
            self.coins.setdefault(d, 0)

    @property
    def total(self) -> int:
        return sum(d * n for d, n in self.coins.items())

    def add(self, denomination: int, count: int = 1) -> None:
        self.coins[denomination] = self.coins.get(denomination, 0) + count

    def merge(self, other: dict[int, int]) -> None:
        for d, n in other.items():
            self.add(d, n)

    def plan_change(self, amount: int) -> dict[int, int] | None:
        """amount를 보유 화폐로 만드는 조합. 불가능하면 None.

        큰 단위 우선으로 탐색하되, 재고가 모자라 막히면 되돌아가 다시 시도한다.
        (그리디로만 가면 500원이 떨어졌고 100원이 넉넉한 경우를 놓친다)
        """

        def search(idx: int, remaining: int) -> dict[int, int] | None:
            if remaining == 0:
                return {}
            if idx >= len(DENOMINATIONS):
                return None

            unit = DENOMINATIONS[idx]
            usable = min(remaining // unit, self.coins.get(unit, 0))
            for use in range(usable, -1, -1):
                rest = search(idx + 1, remaining - unit * use)
                if rest is not None:
                    return {unit: use, **rest} if use else rest
            return None

        return search(0, amount)

    def withdraw(self, plan: dict[int, int]) -> None:
        for d, n in plan.items():
            self.coins[d] -= n

    def describe(self) -> str:
        return " | ".join(f"{won(d)} x {self.coins[d]}" for d in DENOMINATIONS)


class VendingMachine:
    def __init__(self, products: list[Product], cash: CashBox) -> None:
        self.products = {p.code: p for p in products}
        self.cash = cash
        self.inserted = 0
        self.inserted_detail: dict[int, int] = {}
        self.sales = 0

    # --- 현금 ---

    def insert(self, denomination: int) -> str:
        if denomination not in DENOMINATIONS:
            return f"{won(denomination)}은(는) 사용할 수 없습니다. (100/500/1000/5000/10000만 가능)"
        self.inserted += denomination
        self.inserted_detail[denomination] = self.inserted_detail.get(denomination, 0) + 1
        return f"{won(denomination)} 투입.  현재 잔액 {won(self.inserted)}"

    def refund(self) -> str:
        if self.inserted == 0:
            return "반환할 금액이 없습니다."

        # 아직 금고에 섞이지 않았으니 투입한 그대로 돌려준다.
        detail = self.inserted_detail
        amount = self.inserted
        self.inserted = 0
        self.inserted_detail = {}
        return f"{won(amount)} 반환합니다.  ({format_plan(detail)})"

    # --- 구매 ---

    def buy(self, code: str) -> str:
        product = self.products.get(code.upper())
        if product is None:
            return "그런 번호의 상품이 없습니다."
        if product.sold_out:
            return f"[{product.name}] 품절입니다."
        if self.inserted < product.price:
            return f"금액이 부족합니다. {won(product.price - self.inserted)} 더 넣어주세요."

        change_due = self.inserted - product.price

        # 투입금까지 합친 상태에서 거스름돈을 만들 수 있는지 확인한다.
        self.cash.merge(self.inserted_detail)
        plan = self.cash.plan_change(change_due)

        if plan is None:
            # 롤백하고 투입금을 그대로 반환
            for d, n in self.inserted_detail.items():
                self.cash.coins[d] -= n
            return "거스름돈이 부족해 판매할 수 없습니다.\n" + self.refund()

        self.cash.withdraw(plan)
        product.stock -= 1
        self.sales += product.price
        self.inserted = 0
        self.inserted_detail = {}

        lines = [f"[{product.name}] 나왔습니다. 맛있게 드세요."]
        if change_due:
            lines.append(f"거스름돈 {won(change_due)}  ({format_plan(plan)})")
        return "\n".join(lines)

    # --- 표시 ---

    def show_products(self) -> str:
        rows = ["", " 번호  상품             가격      재고", " " + "-" * 42]
        for p in self.products.values():
            stock = "품절" if p.sold_out else f"{p.stock}개"
            buyable = "  <= 구매 가능" if not p.sold_out and p.price <= self.inserted else ""
            rows.append(f" {p.code:<5} {pad(p.name, 16)}{won(p.price):>8}  {pad(stock, 5)}{buyable}")
        rows.append(" " + "-" * 42)
        rows.append(f" 투입 금액: {won(self.inserted)}")
        return "\n".join(rows)


# --- 관리자 ---

ADMIN_PIN = "1234"

# 수금 시 거스름돈용으로 남겨둘 최소 재고
KEEP_FOR_CHANGE = {10000: 0, 5000: 1, 1000: 5, 500: 10, 100: 20}


def read_int(prompt: str) -> int | None:
    raw = input(prompt).strip().replace(",", "").replace("원", "")
    try:
        return int(raw)
    except ValueError:
        print(" 숫자를 입력해주세요.")
        return None


def admin_mode(vm: VendingMachine) -> None:
    if input("관리자 PIN: ").strip() != ADMIN_PIN:
        print("PIN이 틀렸습니다.\n")
        return

    while True:
        print(f"\n[관리자] 누적 매출 {won(vm.sales)} / 금고 {won(vm.cash.total)}")
        print(f"         {vm.cash.describe()}")
        print(" 1) 상품 재고 충전   2) 거스름돈 화폐 충전   3) 수금   0) 나가기")
        sel = input(" > ").strip()

        if sel == "1":
            print(vm.show_products())
            product = vm.products.get(input(" 충전할 상품 번호: ").strip().upper())
            if product is None:
                print(" 없는 상품입니다.")
                continue
            count = read_int(" 몇 개 채울까요? ")
            if count is None or count <= 0:
                continue
            product.stock += count
            print(f" [{product.name}] 재고 {product.stock}개.")

        elif sel == "2":
            print(f" 사용 가능 단위: {', '.join(won(d) for d in DENOMINATIONS)}")
            unit = read_int(" 단위: ")
            if unit not in DENOMINATIONS:
                print(" 취급하지 않는 단위입니다.")
                continue
            count = read_int(" 개수: ")
            if count is None or count <= 0:
                continue
            vm.cash.add(unit, count)
            print(f" {won(unit)} {count}개 충전.")

        elif sel == "3":
            taken: dict[int, int] = {}
            for d in DENOMINATIONS:
                extra = vm.cash.coins[d] - KEEP_FOR_CHANGE.get(d, 0)
                if extra > 0:
                    taken[d] = extra
                    vm.cash.coins[d] -= extra
            amount = sum(d * n for d, n in taken.items())
            print(f" {won(amount)} 수금했습니다.  ({format_plan(taken)})")
            print(f" 거스름돈용 잔여: {vm.cash.describe()}")

        elif sel == "0":
            print(" 관리자 모드를 종료합니다.\n")
            return
        else:
            print(" 없는 메뉴입니다.")


# --- 초기 데이터 ---

def default_machine() -> VendingMachine:
    products = [
        Product("A1", "콜라", 1500, 5),
        Product("A2", "사이다", 1500, 5),
        Product("A3", "이온음료", 1800, 3),
        Product("B1", "생수", 900, 10),
        Product("B2", "캔커피", 1200, 4),
        Product("B3", "우유", 1100, 2),
        Product("C1", "에너지드링크", 2500, 2),
        Product("C2", "옥수수수염차", 1300, 0),  # 품절 상태로 시작
    ]
    cash = CashBox({10000: 0, 5000: 2, 1000: 10, 500: 15, 100: 30})
    return VendingMachine(products, cash)


HELP = """
 명령어
   목록            상품 목록 보기
   투입 <금액>     현금 넣기 (100 / 500 / 1000 / 5000 / 10000)
   <상품번호>      해당 상품 구매 (예: A1)
   반환            투입한 돈 돌려받기
   관리자          관리자 모드 (PIN 1234)
   도움말          이 화면
   종료            프로그램 끝내기
"""


def main() -> None:
    vm = default_machine()
    print("=" * 46)
    print("             자   판   기")
    print("=" * 46)
    print(HELP)
    print(vm.show_products())

    while True:
        try:
            raw = input("\n> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            if vm.inserted:
                print(vm.refund())
            print("이용해 주셔서 감사합니다.")
            return

        if not raw:
            continue

        cmd, _, arg = raw.partition(" ")
        cmd, arg = cmd.strip(), arg.strip()

        if cmd in ("종료", "exit", "quit", "q"):
            if vm.inserted:
                print(vm.refund())
            print("이용해 주셔서 감사합니다.")
            return

        if cmd in ("목록", "메뉴", "ls"):
            print(vm.show_products())
        elif cmd in ("도움말", "help", "?"):
            print(HELP)
        elif cmd in ("투입", "넣기"):
            try:
                value = int(arg.replace(",", "").replace("원", ""))
            except ValueError:
                print("투입할 금액을 숫자로 적어주세요. 예: 투입 1000")
            else:
                print(vm.insert(value))
        elif cmd in ("반환", "환불"):
            print(vm.refund())
        elif cmd in ("관리자", "admin"):
            admin_mode(vm)
        elif cmd.upper() in vm.products:
            print(vm.buy(cmd))
        else:
            print("모르는 명령입니다. '도움말'을 입력해 보세요.")


if __name__ == "__main__":
    main()
