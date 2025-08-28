# config.py

import os

class Config:
    # ... 您现有的配置 ...

    # 数据库配置
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(os.path.abspath(os.path.dirname(__file__)), 'instance', 'smart_urban_system.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # 文件上传配置
    UPLOAD_FOLDER = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'uploads')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

    # JWT 配置 (新增)
    JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "your-super-secret-jwt-key") # **** 替换为更安全的密钥 ****
    # JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1) # 可选：设置访问令牌过期时间
    # JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30) # 可选：设置刷新令牌过期时间
