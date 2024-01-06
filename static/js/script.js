
const btnLogout = document.getElementById("btnLogout");
btnLogout.addEventListener("click", function() {
    Swal.fire({
        icon: "question",
        title: "Logout Confirmation",
        text: "Are you sure you want to log out?",
        showCancelButton: true,
        confirmButtonText: "Yes",
        confirmButtonColor: "#1e40af"
    }).then((result) => {
        if (result.isConfirmed) {
            window.location.href = "/logout";
        }
    });
});


const btnBackward = document.getElementById("btnBackward");
btnBackward.addEventListener("click", function() {
    history.back();
});

const btnForward = document.getElementById("btnForward");
btnForward.addEventListener("click", function() {
    history.forward();
});