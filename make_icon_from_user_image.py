#!/usr/bin/env python3
"""把用户提供的狐狸图片处理成狐径程序图标。"""
import os
from PIL import Image, ImageDraw

SRC = r'C:\Users\kele551\.workbuddy\clipboard-images\clipboard-2026-09-19T13-36-46-576Z-22895be9.png'
OUT = r'C:\Users\kele551\GitHubDirectFix\app.ico'
PREVIEW = r'C:\Users\kele551\GitHubDirectFix\_icon_preview.png'
SIZES = [16, 24, 32, 48, 64, 128, 256]

def remove_white_bg(im, tol=30):
    """从四角 floodfill 背景白色为透明，保留主体内部白色。"""
    im = im.convert('RGBA')
    w, h = im.size
    # 创建遮罩：白色为背景
    mask = Image.new('L', (w, h), 255)  # 255=前景，稍后把背景改成0
    px = im.load()
    from collections import deque
    q = deque()
    visited = set()
    # 从四角开始
    seeds = [(0, 0), (w-1, 0), (0, h-1), (w-1, h-1)]
    for x, y in seeds:
        if (x, y) in visited:
            continue
        r, g, b, a = px[x, y]
        if a < 128 or max(r, g, b) - min(r, g, b) <= tol and r > 240 and g > 240 and b > 240:
            q.append((x, y))
            visited.add((x, y))
    while q:
        x, y = q.popleft()
        mask.putpixel((x, y), 0)
        for dx, dy in [(-1, 0), (1, 0), (0, -1), (0, 1)]:
            nx, ny = x + dx, y + dy
            if nx < 0 or ny < 0 or nx >= w or ny >= h or (nx, ny) in visited:
                continue
            r, g, b, a = px[nx, ny]
            if a < 128 or (max(r, g, b) - min(r, g, b) <= tol and r > 240 and g > 240 and b > 240):
                visited.add((nx, ny))
                q.append((nx, ny))
    # 应用遮罩
    im.putalpha(mask)
    return im

def make_icon():
    # 1. 抠图
    fox = remove_white_bg(Image.open(SRC))
    # 2. 裁剪空白边
    bbox = fox.getbbox()
    fox = fox.crop(bbox)
    # 3. 创建圆角矩形底
    size = 1024
    pad = int(size * 0.10)
    canvas = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(canvas)
    radius = int(size * 0.18)
    # 背景：浅米白到白色的微渐变（横向）
    bg = Image.new('RGBA', (size, size))
    for y in range(size):
        ratio = y / size
        r = int(255 - (255-252) * ratio)
        g = int(255 - (255-246) * ratio)
        b = int(255 - (255-238) * ratio)
        ImageDraw.Draw(bg).line([(0, y), (size, y)], fill=(r, g, b, 255))
    # 画圆角矩形遮罩
    mask = Image.new('L', (size, size), 0)
    ImageDraw.Draw(mask).rounded_rectangle((0, 0, size-1, size-1), radius=radius, fill=255)
    canvas = Image.composite(bg, Image.new('RGBA', (size, size), (0,0,0,0)), mask)
    # 4. 把狐狸缩放到底上，居中
    fx, fy = fox.size
    # 目标高度占画布的 72%
    target_h = int(size * 0.72)
    scale = target_h / fy
    new_w, new_h = int(fx * scale), int(fy * scale)
    fox = fox.resize((new_w, new_h), Image.LANCZOS)
    # 居中
    cx = (size - new_w) // 2
    cy = (size - new_h) // 2
    canvas.alpha_composite(fox, (cx, cy))
    # 5. 加 subtle 投影
    shadow = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    sh_mask = Image.new('L', (size, size), 0)
    ImageDraw.Draw(sh_mask).rounded_rectangle((12, 12, size-1, size-1), radius=radius, fill=30)
    shadow = Image.composite(Image.new('RGBA', (256, 256), (0, 0, 0, 30)), Image.new('RGBA', (size, size), (0,0,0,0)), sh_mask)
    final = Image.alpha_composite(shadow, canvas)
    # 6. 生成 ICO: 用 256x256 作为基础, Pillow 自动缩放生成所有尺寸
    base = final.resize((256, 256), Image.LANCZOS)
    base.save(OUT, format='ICO', sizes=[(s, s) for s in SIZES])
    # 7. 生成预览
    preview = final.resize((256, 256), Image.LANCZOS)
    preview.save(PREVIEW)
    print('图标已保存:', OUT)
    print('尺寸:', final.size)

if __name__ == '__main__':
    make_icon()
