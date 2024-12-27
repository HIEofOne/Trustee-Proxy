const button = document.getElementById("myButton")
button.addEventListener("click", (e) => {
    const button_target = e.target
    window.open(button_target.value)
})