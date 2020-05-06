using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace EsteticasII.ViewModels
{
    public class ResetPasswordViewModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }

        [Required]
        //[StringLength(100, ErrorMessage = "La contraseña debe tener al menos 6 y un máximo de 100 caracteres.", MinimumLength = 6)]
        //[StringLength(100, ErrorMessage = "La  {0} must be at least {2} and at max {1} characters long.", MinimumLength = 6)]
        [StringLength(100, ErrorMessage = "La contraseña {0} debe tener al menos {2} y un máximo de {1} caracteres.", MinimumLength = 6)]
        [DataType(DataType.Password)]
        public string Password { get; set; }

        [DataType(DataType.Password)]
        [Display(Name = "Confirmar contraseña")]
        [Compare("Password", ErrorMessage = "La Contraseña ingresada no coincide con la confirmación de contraseña.")]
        public string ConfirmPassword { get; set; }

        public string Code { get; set; }
    }
}
