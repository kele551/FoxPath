# -*- coding: utf-8 -*-
"""生成「狐径 FoxPath」应用图标（Low Poly + 自然渐变过渡风格）。

设计要点：
- 圆角矩形深色底
- 狐狸头先做一个从上到下的橙渐变，再切割出低多边形
- 耳朵自然地从脸部亮部延伸出来，没有色块断层
- 用细暗线保留 low-poly 的切割感
- 1024×1024 绘制，LANCZOS 缩放到 16-256
"""
from PIL import Image, ImageDraw

OUT = r'C:\Users\kele551\GitHubDirectFix\app.ico'
CANVAS = 1024


def hex_rgba(hex_color, alpha=255):
    h = hex_color.lstrip('#')
    r, g, b = tuple(int(h[i:i+2], 16) for i in (0, 2, 4))
    return (r, g, b, alpha)


def lerp_color(c1, c2, t):
    return tuple(int(c1[i] + (c2[i] - c1[i]) * t) for i in range(4))


def multi_gradient(img, stops):
    """stops: [(y_ratio, color_rgba), ...] 按 y 位置做分段线性渐变。"""
    draw = ImageDraw.Draw(img)
    h = img.height
    sorted_stops = sorted(stops, key=lambda x: x[0])
    for y in range(h):
        t = y / h
        # 找到当前 t 所在区间
        for i in range(len(sorted_stops) - 1):
            t0, c0 = sorted_stops[i]
            t1, c1 = sorted_stops[i + 1]
            if t0 <= t <= t1:
                local_t = (t - t0) / max(1e-6, t1 - t0)
                c = lerp_color(c0, c1, local_t)
                break
        else:
            c = sorted_stops[-1][1]
        draw.line([(0, y), (img.width, y)], fill=c)


def round_rect_mask(size, radius):
    mask = Image.new('L', size, 0)
    d = ImageDraw.Draw(mask)
    d.rounded_rectangle([0, 0, size[0]-1, size[1]-1], radius=radius, fill=255)
    return mask


def draw_icon(canvas=CANVAS):
    s = canvas
    img = Image.new('RGBA', (s, s), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    pad = s // 18
    r = s // 10

    # 背景
    bg = Image.new('RGBA', (s, s), hex_rgba('#1a1d24'))
    mask = round_rect_mask((s, s), r)
    bg.putalpha(mask)
    img.alpha_composite(bg)
    draw.rounded_rectangle([pad, pad, s-pad, s-pad], radius=r,
                           outline=(255, 255, 255, 25), width=2)

    # 投影
    shadow = Image.new('RGBA', (s, s), (0, 0, 0, 0))
    sd = ImageDraw.Draw(shadow)
    sd.rounded_rectangle([pad+5, pad+5, s-pad+5, s-pad+5], radius=r,
                         fill=(0, 0, 0, 45))
    img.alpha_composite(shadow)

    cx = s // 2
    top = int(s * 0.18)
    chin = int(s * 0.78)
    eye_y = int(s * 0.44)
    nose_y = int(s * 0.66)

    # 耳朵三角形
    left_ear = [(cx, top), (cx - int(s*0.12), top + int(s*0.18)), (cx - int(s*0.28), top + int(s*0.05))]
    left_ear2 = [(cx - int(s*0.28), top + int(s*0.05)), (cx - int(s*0.12), top + int(s*0.18)), (cx - int(s*0.22), top + int(s*0.28))]
    right_ear = [(cx, top), (cx + int(s*0.12), top + int(s*0.18)), (cx + int(s*0.28), top + int(s*0.05))]
    right_ear2 = [(cx + int(s*0.28), top + int(s*0.05)), (cx + int(s*0.12), top + int(s*0.18)), (cx + int(s*0.22), top + int(s*0.28))]

    # 低多边形边线（用于在渐变层上画切割线）
    edges = [
        # 耳朵线
        (left_ear[0], left_ear[1]), (left_ear[1], left_ear[2]), (left_ear[2], left_ear[0]),
        (left_ear2[0], left_ear2[1]), (left_ear2[1], left_ear2[2]), (left_ear2[2], left_ear2[0]),
        (right_ear[0], right_ear[1]), (right_ear[1], right_ear[2]), (right_ear[2], right_ear[0]),
        (right_ear2[0], right_ear2[1]), (right_ear2[1], right_ear2[2]), (right_ear2[2], right_ear2[0]),
        # 脸部 low-poly 线
        ((cx - int(s*0.12), top + int(s*0.18)), (cx + int(s*0.12), top + int(s*0.18))),
        ((cx - int(s*0.12), top + int(s*0.18)), (cx, eye_y)),
        ((cx + int(s*0.12), top + int(s*0.18)), (cx, eye_y)),
        ((cx - int(s*0.22), top + int(s*0.28)), (cx, eye_y)),
        ((cx + int(s*0.22), top + int(s*0.28)), (cx, eye_y)),
        ((cx - int(s*0.22), top + int(s*0.28)), (cx - int(s*0.26), eye_y + int(s*0.12))),
        ((cx + int(s*0.22), top + int(s*0.28)), (cx + int(s*0.26), eye_y + int(s*0.12))),
        ((cx - int(s*0.26), eye_y + int(s*0.12)), (cx, nose_y)),
        ((cx + int(s*0.26), eye_y + int(s*0.12)), (cx, nose_y)),
        ((cx - int(s*0.26), eye_y + int(s*0.12)), (cx - int(s*0.20), chin)),
        ((cx + int(s*0.26), eye_y + int(s*0.12)), (cx + int(s*0.20), chin)),
        ((cx - int(s*0.20), chin), (cx, chin + int(s*0.06))),
        ((cx + int(s*0.20), chin), (cx, chin + int(s*0.06))),
        ((cx - int(s*0.20), chin), (cx, nose_y)),
        ((cx + int(s*0.20), chin), (cx, nose_y)),
    ]

    # 创建渐变层：头顶亮 → 下巴暗，耳朵自然继承脸部顶部的亮色
    gradient = Image.new('RGBA', (s, s), (0, 0, 0, 0))
    multi_gradient(gradient, [
        (0.0, hex_rgba('#fdba74')),
        (0.25, hex_rgba('#fb923c')),
        (0.50, hex_rgba('#f97316')),
        (0.75, hex_rgba('#ea580c')),
        (1.0, hex_rgba('#c2410c')),
    ])

    # 狐狸头形状 mask
    shape_mask = Image.new('L', (s, s), 0)
    sm = ImageDraw.Draw(shape_mask)
    face_r = int(s * 0.30)
    face_top = top + int(s * 0.10)
    face_bottom = chin + int(s * 0.06)
    sm.ellipse([cx - face_r, face_top, cx + face_r, face_bottom], fill=255)
    sm.polygon(left_ear, fill=255)
    sm.polygon(left_ear2, fill=255)
    sm.polygon(right_ear, fill=255)
    sm.polygon(right_ear2, fill=255)
    # 耳根接顺
    sm.ellipse([cx - int(s*0.20), face_top - int(s*0.08), cx + int(s*0.20), face_top + int(s*0.08)], fill=255)
    gradient.putalpha(shape_mask)
    img.alpha_composite(gradient)

    # 画低多边形细线（切割感）
    line_col = (20, 20, 20, 50)
    for a, b in edges:
        draw.line([a, b], fill=line_col, width=2)

    # 眼睛：白色小菱形
    eye_size = int(s * 0.022)
    for dx in (-int(s*0.12), int(s*0.12)):
        ex = cx + dx
        draw.polygon([
            (ex, eye_y - eye_size),
            (ex + eye_size, eye_y),
            (ex, eye_y + eye_size),
            (ex - eye_size, eye_y),
        ], fill=hex_rgba('#ffffff'))

    # 鼻子：黑色小三角
    draw.polygon([
        (cx, nose_y - int(s*0.01)),
        (cx - int(s*0.018), nose_y + int(s*0.02)),
        (cx + int(s*0.018), nose_y + int(s*0.02)),
    ], fill=hex_rgba('#1f2937'))

    return img


def make_icon():
    master = draw_icon(CANVAS)
    sizes = [256, 128, 64, 48, 32, 16]
    images = []
    for s in sizes:
        im = master.resize((s, s), Image.LANCZOS)
        images.append(im)
    images[0].save(
        OUT,
        format='ICO',
        sizes=[(s, s) for s in sizes],
        append_images=images[1:],
    )
    print('saved', OUT, 'sizes=', sizes)


if __name__ == '__main__':
    make_icon()
