// Cierra alertas automáticamente después de 5 segundos
document.addEventListener('DOMContentLoaded', function () {
  document.querySelectorAll('.alert.alert-success, .alert.alert-info').forEach(function (el) {
    setTimeout(function () {
      var bsAlert = new bootstrap.Alert(el);
      bsAlert.close();
    }, 5000);
  });
});
