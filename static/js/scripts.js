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
});