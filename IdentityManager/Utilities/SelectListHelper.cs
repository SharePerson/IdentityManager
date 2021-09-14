using Microsoft.AspNetCore.Mvc.Rendering;
using System.Collections.Generic;
using System.Linq;

namespace IdentityManager.Utilities
{
    public static class SelectListHelper
    {
        public static List<SelectListItem> ToSelectListItem<T>(this List<T> items, string textPropertyName, int selectedValue = 0)
        {
            return items.Select(item => new SelectListItem
            {
                Text = item.GetPropertyValue(textPropertyName),
                Value = item.GetPropertyValue("Id"),
                Selected = item.GetPropertyValue("Id").Equals(selectedValue)
            }).ToList();
        }

        public static string GetPropertyValue<T>(this T item, string propertyName)
        {
            return item.GetType().GetProperty(propertyName).GetValue(item, null).ToString();
        }
    }
}
