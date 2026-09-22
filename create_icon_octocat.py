# -*- coding: utf-8 -*-
"""按 Octocat 的形状手绘一张高分辨率图标（不放大原图，避免糊）。

- 深色圆角底
- 白色 Octocat 剪影：圆头 + 两只尖耳 + 章鱼触手
- 1024×1024 绘制，LANCZOS 缩放到 16-256
"""
from PIL import Image, ImageDraw

OUT = r'C:\Users\kele551\GitHubDirectFix\app.ico'
CANVAS = 1024

BG = (26, 29, 36, 255)        # 深色底
BODY = (240, 243, 247, 255)   # Octocat 主体（近白）
EYE = (26, 29, 36, 255)       # 眼睛挖空用底色


def round_rect_mask(size, radius):
    mask = Image.new('L', size, 0)
    d = ImageDraw.Draw(mask)
    d.rounded_rectangle([0, 0, size[0] - 1, size[1] - 1], radius=radius, fill=255)
    return mask


def draw_icon(canvas=CANVAS):
    s = canvas
    img = Image.new('RGBA', (s, s), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    pad = s // 18
    r = s // 10

    # 深色圆角底
    base = Image.new('RGBA', (s, s), BG)
    base.putalpha(round_rect_mask((s, s), r))
    img.alpha_composite(base)
    draw.rounded_rectangle([pad, pad, s - pad, s - pad], radius=r,
                           outline=(255, 255, 255, 26), width=2)

    cx = s // 2
    head_cy = int(s * 0.42)
    head_rx = int(s * 0.25)
    head_ry = int(s * 0.23)

    # ---- 触手：底部 5 条，向外张开并卷曲 ----
    tentacles = [
        # (起点x偏移, 起点y偏移, 控制点, 末端卷曲半径)
        (-0.20, 0.58, -0.30, 0.74, 0.055),
        (-0.10, 0.60, -0.14, 0.78, 0.050),
        (0.00, 0.61, 0.00, 0.80, 0.048),
        (0.10, 0.60, 0.14, 0.78, 0.050),
        (0.20, 0.58, 0.30, 0.74, 0.055),
    ]
    for x0, y0, x1, y1, tr in tentacles:
        p0 = (cx + int(s * x0), int(s * y0))
        p1 = (cx + int(s * x1), int(s * y1))
        width = int(s * 0.075)
        # 粗线做触手主体
        draw.line([p0, p1], fill=BODY, width=width, joint='curve')
        # 末端卷曲小圆
        tr_px = int(s * tr)
        draw.ellipse([p1[0] - tr_px, p1[1] - tr_px, p1[0] + tr_px, p1[1] + tr_px],
                     fill=BODY)
        # 起点补圆，和身体接顺
        sr = width // 2
        draw.ellipse([p0[0] - sr, p0[1] - sr, p0[0] + sr, p0[1] + sr], fill=BODY)

    # ---- 耳朵：头顶两只尖三角 ----
    ear_h = int(s * 0.14)
    ear_w = int(s * 0.13)
    ear_y = head_cy - head_ry + int(s * 0.02)
    for sign in (-1, 1):
        bx = cx + sign * int(s * 0.15)
        draw.polygon([
            (bx - ear_w // 2, ear_y + int(s * 0.03)),
            (bx + sign * ear_w // 2, ear_y - ear_h),
            (bx + ear_w // 2, ear_y + int(s * 0.03)),
        ], fill=BODY)

    # ---- 头：大椭圆 ----
    draw.ellipse([cx - head_rx, head_cy - head_ry, cx + head_rx, head_cy + head_ry],
                 fill=BODY)

    # ---- 眼睛：用底色挖两个洞，做出 Octocat 的表情 ----
    eye_rx = int(s * 0.055)
    eye_ry = int(s * 0.070)
    eye_y = head_cy - int(s * 0.02)
    eye_dx = int(s * 0.10)
    for sign in (-1, 1):
        ex = cx + sign * eye_dx
        draw.ellipse([ex - eye_rx, eye_y - eye_ry, ex + eye_rx, eye_y + eye_ry],
                     fill=EYE)

    return img


def make_icon():
    master = draw_icon(CANVAS)
    sizes = [256, 128, 64, 48, 32, 16]
    images = [master.resize((sz, sz), Image.LANCZOS) for sz in sizes]
    images[0].save(
        OUT,
        format='ICO',
        sizes=[(sz, sz) for sz in sizes],
        append_images=images[1:],
    )
    print('saved', OUT, 'sizes=', sizes)
    master.resize((256, 256), Image.LANCZOS).save(
        r'C:\Users\kele551\GitHubDirectFix\_fox_preview.png')
    print('preview saved')


if __name__ == '__main__':
    make_icon()
