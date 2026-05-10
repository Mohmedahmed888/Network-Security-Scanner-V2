"""
Create icon.ico file for the application
"""

from PIL import Image, ImageDraw, ImageFont
import os

try:
    # Create icon image
    size = 256
    img = Image.new('RGB', (size, size), color='#0f1115')
    draw = ImageDraw.Draw(img)
    
    # Draw shield/circle background
    margin = 20
    draw.ellipse([margin, margin, size-margin, size-margin], fill='#1f6feb', outline='#58a6ff', width=5)
    
    # Draw network waves
    center = size // 2
    for i in range(3):
        radius = 30 + i * 15
        y = center + 10
        # Draw arc (top half of circle)
        draw.arc([center-radius, y-radius, center+radius, y+radius], 
                 start=0, end=180, fill='#ffffff', width=4)
    
    # Draw text "NS" in center
    try:
        # Try to use a font, fallback to default if not available
        font = ImageFont.truetype("arial.ttf", 60)
    except:
        font = ImageFont.load_default()
    
    draw.text((center-30, center-40), "NS", fill='#ffffff', font=font)
    
    # Convert to ICO format
    img.save('icon.ico', format='ICO', sizes=[(256, 256), (128, 128), (64, 64), (32, 32), (16, 16)])
    print("Icon created: icon.ico")
    
except ImportError:
    print("PIL not installed. Creating simple icon using alternative method...")
    # Create a simple .ico file header (minimal valid ICO)
    # This is a fallback if PIL is not available
    ico_data = bytes([
        0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x20, 0x20, 0x00, 0x00, 0x01, 0x00,
        0x20, 0x00, 0xA8, 0x10, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00, 0x28, 0x00,
        0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x01, 0x00,
        0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00
    ] + [0x00] * 4000)  # Simple blue square
    
    with open('icon.ico', 'wb') as f:
        f.write(ico_data)
    print("Simple icon created: icon.ico")
    print("Tip: Install Pillow for better icon: pip install Pillow")


