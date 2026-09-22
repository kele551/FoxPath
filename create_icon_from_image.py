# -*- coding: utf-8 -*-
"""把用户给的 Octocat 素材图(49x41)转成应用图标 ICO。

处理流程：
1. 读原图，按亮度阈值抠出深色主体（去掉浅米色背景）
2. 裁掉四周空白，把主体居中
3. 放到深色圆角矩形底上
4. 1024×1024 画布，LANCZOS 缩放到 16-256 各尺寸
"""
import os
from PIL import Image, ImageDraw, ImageFilter

SRC = r'F:\文档\xwechat_files\wxid_rbb9gkv7o3bj22_fc75\temp\InputTemp\d2b554e6-e4cb-49fe-903c-981b4c9dd9d3.png'
OUT = r'C:\Users\kele551\GitHubDirectFix\app.ico'
CANVAS = 1024


def round_rect_mask(size, radius):
    mask = Image.new('L', size, 0)
    d = ImageDraw.Draw(mask)
    d.rounded_rectangle([0, 0, size[0] - 1, size[1] - 1], radius=radius, fill=255)
    return mask


def extract_subject(src_path):
    """抠出深色主体，返回 RGBA 图（背景透明）。"""
    im = Image.open(src_path).convert('RGBA')
    g = im.convert('L')

    # 主体 = 暗部。用阈值把浅色背景剔掉。
    # 原图背景约 230，主体约 15-60
    mask = g.point(lambda v: 255 if v < 140 else 0)

    # 去孤立噪点
    mask = mask.filter(ImageFilter.MedianFilter(size=3))

    out = Image.new('RGBA', im.size, (0, 0, 0, 0))
    # 主体填成接近原图的深黑，但稍微提亮一点点，避免糊成一团
    solid = Image.new('RGBA', im.size, (24, 26, 30, 255))
    out.paste(solid, (0, 0), mask)
    return out, mask


def trim_to_square(im, mask):
    """按 mask 裁掉空白，再补成正方形并居中。"""
    bbox = mask.getbbox()
    if not bbox:
        return im
    im = im.crop(bbox)
    w, h = im.size
    side = max(w, h)
    canvas = Image.new('RGBA', (side, side), (0, 0, 0, 0))
    canvas.paste(im, ((side - w) // 2, (side - h) // 2), im)
    return canvas


def build():
    subject, mask = extract_subject(SRC)
    subject = trim_to_square(subject, mask)

    s = CANVAS
    img = Image.new('RGBA', (s, s), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    pad = s // 18
    r = s // 10

    # 深色圆角底（和 Octocat 的 GitHub 黑呼应）
    base = Image.new('RGBA', (s, s), (24, 27, 33, 255))
    base.putalpha(round_rect_mask((s, s), r))
    img.alpha_composite(base)

    # 细描边
    draw.rounded_rectangle([pad, pad, s - pad, s - pad], radius=r,
                           outline=(255, 255, 255, 28), width=2)

    # 主体缩放到画布的 72%，居中
    target = int(s * 0.72)
    subj = subject.resize((target, target), Image.LANCZOS)
    # 轻微锐化，缓解小图放大的糊感
    subj = subj.filter(ImageFilter.UnsharpMask(radius=2, percent=60, threshold=3))
    img.alpha_composite(subj, ((s - target) // 2, (s - target) // 2))

    sizes = [256, 128, 64, 48, 32, 16]
    images = [img.resize((sz, sz), Image.LANCZOS) for sz in sizes]
    images[0].save(
        OUT,
        format='ICO',
        sizes=[(sz, sz) for sz in sizes],
        append_images=images[1:],
    )
    print('saved', OUT, 'sizes=', sizes)
    img.resize((256, 256), Image.LANCZOS).save(
        r'C:\Users\kele551\GitHubDirectFix\_fox_preview.png')
    print('preview saved')


if __name__ == '__main__':
    build()
