from PIL import Image, ImageDraw

def make_circle(img_path, output_path):
    # Open the image and convert to RGBA
    img = Image.open(img_path).convert("RGBA")
    
    # Create a circular mask
    mask = Image.new("L", img.size, 0)
    draw = ImageDraw.Draw(mask)
    draw.ellipse((0, 0) + img.size, fill=255)
    
    # Apply the mask
    img.putalpha(mask)
    
    # Save the result
    img.save(output_path)

if __name__ == "__main__":
    make_circle("public/open_intel_logo.png", "public/logo_circle.png")
