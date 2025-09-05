import argparse
import xlrd
from app import app, db, Product, _normalize_text


def norm_header(s):
    try:
        s = '' if s is None else str(s)
    except Exception:
        s = ''
    return s.strip().lower()


def to_float(x):
    try:
        return float(str(x).replace(',', '.'))
    except Exception:
        return None


def to_int(x):
    try:
        return int(float(str(x).replace(',', '.')))
    except Exception:
        return None


def parse_xls(path):
    wb = xlrd.open_workbook(path)
    sh = wb.sheet_by_index(0)

    # choose header row with the most non-empty cells among first 50 rows
    header_row = 0
    best_count = -1
    headers = [norm_header(sh.cell_value(0, c)) for c in range(sh.ncols)]
    scan_limit = min(50, sh.nrows)
    for r in range(scan_limit):
        heads_try = [norm_header(sh.cell_value(r, c)) for c in range(sh.ncols)]
        count = sum(1 for h in heads_try if h)
        if count > best_count:
            best_count = count
            header_row = r
            headers = heads_try

    # build index map
    idx = {}
    for i, h in enumerate(headers):
        if any(x in h for x in ('наимен', 'товар', 'назван')):
            idx['name'] = i
        if ('код' in h and 'штрих' not in h) or 'артикул' in h:
            idx.setdefault('sku', i)
        if 'штрих' in h:
            idx.setdefault('barcode', i)
        if any(x in h for x in ('себесто', 'закуп', 'покуп')):
            idx.setdefault('cost_price', i)
        if ('цена' in h and 'сумм' not in h) or 'розниц' in h or 'продаж' in h:
            idx.setdefault('base_price', i)
        if any(x in h for x in ('остаток', 'доступ', 'кол-во', 'количество')):
            idx.setdefault('stock_qty', i)

    rows = []
    for r in range(header_row + 1, sh.nrows):
        def get(k):
            i = idx.get(k)
            return sh.cell_value(r, i) if i is not None and i < sh.ncols else None
        name = (str(get('name')).strip() if get('name') is not None else '')
        if not name:
            continue
        sku = (str(get('sku')).strip() if get('sku') is not None else None) or None
        barcode = (str(get('barcode')).strip() if get('barcode') is not None else None) or None
        image_url = None
        cost = to_float(get('cost_price'))
        base = to_float(get('base_price'))
        qty = to_int(get('stock_qty'))
        rows.append(dict(name=name, sku=sku, barcode=barcode, image_url=image_url, cost_price=cost, base_price=base, stock_qty=qty))
    return rows


def upsert_products(rows, update_if_exists=True):
    added = updated = skipped = 0
    for r in rows:
        name = r['name']
        sku = r['sku']
        barcode = r['barcode']
        image_url = r['image_url']
        cost = r['cost_price'] if r['cost_price'] is not None else 0.0
        base = r['base_price'] if r['base_price'] is not None else 0.0
        qty = r['stock_qty'] if r['stock_qty'] is not None else 0

        found = None
        if sku:
            found = Product.query.filter_by(sku=sku).first()
        if not found and barcode:
            found = Product.query.filter_by(barcode=barcode).first()
        if not found:
            found = Product.query.filter_by(name=name).first()

        if found:
            if update_if_exists:
                if found.sku != sku:
                    found.sku = sku
                if found.barcode != barcode:
                    found.barcode = barcode
                if found.image_url != image_url:
                    found.image_url = image_url
                if found.cost_price != cost:
                    found.cost_price = cost
                if found.base_price != base:
                    found.base_price = base
                if qty is not None:
                    found.stock_qty = qty
                found.search_text = _normalize_text(' '.join(filter(None, [found.name, found.sku, found.barcode])))
                updated += 1
            else:
                skipped += 1
        else:
            p = Product(name=name, sku=sku, barcode=barcode, image_url=image_url, cost_price=cost, base_price=base, stock_qty=qty)
            p.search_text = _normalize_text(' '.join(filter(None, [p.name, p.sku, p.barcode])))
            db.session.add(p)
            added += 1

    db.session.commit()
    return added, updated, skipped


def main():
    ap = argparse.ArgumentParser(description='Импорт/обновление товаров из .xls')
    ap.add_argument('path', help='Путь к .xls файлу')
    ap.add_argument('--no-update', action='store_true', help='Не обновлять существующие записи')
    args = ap.parse_args()

    with app.app_context():
        rows = parse_xls(args.path)
        a, u, s = upsert_products(rows, update_if_exists=not args.no_update)
        print(f'Импорт завершён: добавлено {a}, обновлено {u}, пропущено {s}.')


if __name__ == '__main__':
    main()


