from PIL import Image
import os
import struct

def embed_watermark(carrier_path, watermark_path, output_path):

    # 打开载体图片和水印图片
    carrier_img = Image.open(carrier_path).convert("RGB")
    watermark_img = Image.open(watermark_path).convert("RGB")
    
    # 检查载体图片是否足够大
    carrier_width, carrier_height = carrier_img.size
    watermark_width, watermark_height = watermark_img.size
    carrier_capacity = carrier_width * carrier_height * 3  # 每个像素3位
    watermark_size = watermark_width * watermark_height * 3 * 8  # 每个像素3字节×8位
    
    # 需要额外存储头信息（宽度4字节，高度4字节）
    header_size = 8 * 8  # 8字节×8位/字节
    
    if watermark_size + header_size > carrier_capacity:
        raise ValueError(f"载体图片太小，无法容纳水印图片。需要: {watermark_size + header_size} 位, 可用: {carrier_capacity} 位")
    
    # 将水印图片转换为二进制字符串
    watermark_bin = ""
    for pixel in watermark_img.getdata():
        for value in pixel:
            watermark_bin += bin(value)[2:].zfill(8)
    
    # 创建头信息（宽度和高度各4字节）
    header_bin = bin(watermark_width)[2:].zfill(32) + bin(watermark_height)[2:].zfill(32)
    
    # 合并头信息和水印数据
    full_data = header_bin + watermark_bin
    total_bits = len(full_data)
    
    # 将水印数据嵌入载体图片
    carrier_data = list(carrier_img.getdata())
    new_data = []
    data_index = 0
    
    for pixel in carrier_data:
        if data_index >= total_bits:
            new_data.append(pixel)
            continue
            
        r, g, b = pixel
        # 嵌入R通道
        r = (r & 0xFE) | int(full_data[data_index])
        data_index += 1
        
        # 如果还有数据，嵌入G通道
        if data_index < total_bits:
            g = (g & 0xFE) | int(full_data[data_index])
            data_index += 1
        else:
            new_data.append((r, g, b))
            continue
            
        # 如果还有数据，嵌入B通道
        if data_index < total_bits:
            b = (b & 0xFE) | int(full_data[data_index])
            data_index += 1
            
        new_data.append((r, g, b))
    
    # 保存含水印的图片
    watermarked_img = Image.new("RGB", carrier_img.size)
    watermarked_img.putdata(new_data)
    
    # 确保使用PNG格式保存（无损）
    if not output_path.lower().endswith('.png'):
        output_path += '.png'
    
    watermarked_img.save(output_path)
    print(f"水印嵌入成功! 输出文件: {output_path}")
    return watermarked_img

def extract_watermark(watermarked_path, output_path):

    # 打开含水印图片
    watermarked_img = Image.open(watermarked_path).convert("RGB")
    pixel_data = list(watermarked_img.getdata())
    
    # 提取头信息（宽度和高度各4字节 = 32位）
    header_bin = ""
    bits_extracted = 0
    header_bits_needed = 64  # 32位宽度 + 32位高度
    
    for pixel in pixel_data:
        r, g, b = pixel
        
        # 提取R通道的LSB
        header_bin += str(r & 1)
        bits_extracted += 1
        if bits_extracted >= header_bits_needed:
            break
            
        # 提取G通道的LSB
        header_bin += str(g & 1)
        bits_extracted += 1
        if bits_extracted >= header_bits_needed:
            break
            
        # 提取B通道的LSB
        header_bin += str(b & 1)
        bits_extracted += 1
        if bits_extracted >= header_bits_needed:
            break
    
    if len(header_bin) < header_bits_needed:
        raise ValueError("无法提取完整的头信息")
    
    # 解析宽度和高度
    width_bin = header_bin[:32]
    height_bin = header_bin[32:64]
    
    try:
        width = int(width_bin, 2)
        height = int(height_bin, 2)
    except:
        raise ValueError("无法解析水印尺寸信息")
    
    print(f"提取的水印尺寸: {width}×{height} 像素")
    
    # 计算水印数据总位数
    watermark_bits_needed = width * height * 3 * 8
    
    # 提取水印数据（跳过已读取的头信息）
    watermark_bin = ""
    current_index = bits_extracted // 3  # 已经处理的像素数
    if bits_extracted % 3 != 0:
        current_index += 1
    
    bits_extracted = 0
    
    # 继续提取剩余像素
    for i in range(current_index, len(pixel_data)):
        if bits_extracted >= watermark_bits_needed:
            break
            
        r, g, b = pixel_data[i]
        
        # 提取R通道
        watermark_bin += str(r & 1)
        bits_extracted += 1
        if bits_extracted >= watermark_bits_needed:
            break
            
        # 提取G通道
        watermark_bin += str(g & 1)
        bits_extracted += 1
        if bits_extracted >= watermark_bits_needed:
            break
            
        # 提取B通道
        watermark_bin += str(b & 1)
        bits_extracted += 1
        if bits_extracted >= watermark_bits_needed:
            break
    
    # 将二进制数据转换为像素值
    watermark_data = []
    for i in range(0, min(len(watermark_bin), watermark_bits_needed), 8):
        if i + 8 > len(watermark_bin):
            break
        byte = watermark_bin[i:i+8]
        watermark_data.append(int(byte, 2))
    
    # 确保数据长度匹配图像尺寸
    expected_pixels = width * height
    expected_values = expected_pixels * 3
    if len(watermark_data) < expected_values:
        # 填充缺失数据为黑色
        watermark_data.extend([0] * (expected_values - len(watermark_data)))
    
    # 创建水印图片
    watermark_img = Image.new("RGB", (width, height))
    
    # 将数据组织为RGB元组
    pixels = []
    for i in range(0, len(watermark_data), 3):
        r = watermark_data[i] if i < len(watermark_data) else 0
        g = watermark_data[i+1] if i+1 < len(watermark_data) else 0
        b = watermark_data[i+2] if i+2 < len(watermark_data) else 0
        pixels.append((r, g, b))
    
    watermark_img.putdata(pixels[:expected_pixels])
    
    # 确保使用PNG格式保存
    if not output_path.lower().endswith('.png'):
        output_path += '.png'
    
    watermark_img.save(output_path)
    print(f"水印提取成功! 输出文件: {output_path}")
    return watermark_img

if __name__ == "__main__":

    carrier_image = "example1.png"
    watermark_image = "example2.png"
    watermarked_image = "example_im.png"
    extracted_watermark = "extracted_example.png"
    
    try:
        # 嵌入水印
        watermarked = embed_watermark(carrier_image, watermark_image, watermarked_image)
        
        # 提取水印
        extracted = extract_watermark(watermarked_image, extracted_watermark)
        extracted.show()
        
    except Exception as e:
        print(f"错误: {e}")