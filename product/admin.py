from django.contrib import admin
from product.models import *
from product.abstract import *

class ProductImageAdmin(admin.StackedInline):
    model = ProductImage
class ProductInformationAdmin(admin.StackedInline):
    model = ProductInformation
@admin.register(Product)
class ProductAdmin(admin.ModelAdmin):
    list_display = ('title', 'price', 'discount', 'is_trend', 'is_up')
    inlines = (ProductImageAdmin, ProductInformationAdmin, )

@admin.register(Category, Size, Color, Brand, ProductInformation, ProductImage)
class Admin(admin.ModelAdmin):
    pass