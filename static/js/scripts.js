// 页面加载完成后初始化
document.addEventListener('DOMContentLoaded', () => {
    // 为所有帖子添加点击效果
    document.querySelectorAll('.post').forEach(post => {
        post.addEventListener('click', () => {
            post.style.transform = 'scale(0.98)';
            setTimeout(() => post.style.transform = '', 200);
        });
    });

    // 表单输入动画
    document.querySelectorAll('input, textarea').forEach(input => {
        input.addEventListener('focus', () => {
            input.parentElement.style.transform = 'scale(1.02)';
        });
        input.addEventListener('blur', () => {
            input.parentElement.style.transform = '';
        });
    });

    // 添加头像修改逻辑
    const changeAvatarBtn = document.getElementById('change-avatar-btn');
    const avatarModal = document.getElementById('avatar-modal');
    const closeBtn = document.getElementsByClassName('close')[0];
    const avatarCropper = document.getElementById('avatar-cropper');
    const cropAvatarBtn = document.getElementById('crop-avatar-btn');
    const cancelAvatarBtn = document.getElementById('cancel-avatar-btn');

    changeAvatarBtn.addEventListener('click', () => {
        const input = document.createElement('input');
        input.type = 'file';
        input.accept = 'image/*';
        input.onchange = (e) => {
            const file = e.target.files[0];
            if (file) {
                const reader = new FileReader();
                reader.onload = (e) => {
                    avatarCropper.src = e.target.result;
                    avatarModal.style.display = 'block';
                };
                reader.readAsDataURL(file);
            }
        };
        input.click();
    });

    closeBtn.addEventListener('click', () => {
        avatarModal.style.display = 'none';
    });

    window.onclick = (event) => {
        if (event.target == avatarModal) {
            avatarModal.style.display = 'none';
        }
    };

    cropAvatarBtn.addEventListener('click', () => {
        // 这里需要添加裁剪图片并上传的逻辑
        // 使用 cropper.js 进行裁剪
        const cropper = new Cropper(avatarCropper, {
            aspectRatio: 1,
            viewMode: 1,
        });
        cropper.getCroppedCanvas().toBlob((blob) => {
            const formData = new FormData();
            formData.append('avatar', blob, 'avatar.png');
            fetch('/change_avatar', {
                method: 'POST',
                body: formData,
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    document.getElementById('avatar-preview').src = URL.createObjectURL(blob);
                    avatarModal.style.display = 'none';
                    alert('头像修改成功，喵~~~');
                } else {
                    alert('头像修改失败，请重试哦！');
                }
            });
        });
    });

    cancelAvatarBtn.addEventListener('click', () => {
        avatarModal.style.display = 'none';
    });
});