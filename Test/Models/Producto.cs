using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace Test.Models
{
    public class Producto
    {
        public short ID_Producto { get; set; }

        [Required(ErrorMessage = "El Instrumento es Requerida")]
        [StringLength(100, ErrorMessage = "El Instrumento acepta de dos (2) a cien (100) caracteres", MinimumLength = 2)]
        [Display(Name = "Instrumento")]
        public string TX_NombreProducto { get; set; }

        public string TX_Serial_Producto { get; set; }

        public byte? ID_Proveedor { get; set; }
    }
}
