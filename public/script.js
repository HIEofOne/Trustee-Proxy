const wrapper = document.querySelector(".wrapper"),
generateBtn = wrapper.querySelector(".form button");

generateBtn.addEventListener("click", (e) => {
    const button = e.target
    window.open(button.value)
});