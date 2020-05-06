using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace EsteticasII.ViewModels
{
    public class LoginViewModel
    {
        [EmailAddress]
        [DataType(DataType.EmailAddress)]
        [Display(Name = "Correo electrónico")]
        public string Email { get; set; }

        [Display(Name = "Usuario")]
        public string User { get; set; }

        [DataType(DataType.Password)]
        [Display(Name = "Contraseña")]
        [Required(ErrorMessage = "Debe indicar una contraseña")]
        public string Password { get; set; }

        [Display(Name = "Recuérdame")]
        public bool RememberMe { get; set; }
    }
}
