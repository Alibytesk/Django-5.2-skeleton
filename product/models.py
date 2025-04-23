from django.db import models
from django.urls import reverse
from django.utils.text import slugify
from product.abstract import *


class Product(AbstractBaseTimeControl):
    slug = models.SlugField(unique=True, blank=True, null=True)
    title = models.CharField(max_length=255)
    description = models.TextField()
    price = models.FloatField()
    discount = models.SmallIntegerField()
    brand = models.OneToOneField(Brand, on_delete=models.CASCADE, related_name='brand', null=True, blank=True)
    category = models.ManyToManyField(Category, related_name='category', blank=True)
    size = models.ManyToManyField(Size, related_name='size', blank=True)
    color = models.ManyToManyField(Color, related_name='color', blank=True)
    is_trend = models.BooleanField(default=False)
    is_up = models.BooleanField(default=False)

    def get_absolute_url(self):
        return reverse('account:detail', **{'slug': self.slug})

    def save(self, *args, **kwargs):
        self.slug = slugify(self.title)
        super(Product, self).save(*args, **kwargs)

    def __str__(self):
        return f"{self.title} ${self.price} %{self.discount} {self.description[:20]}..."


class ProductImage(models.Model):
    product = models.ForeignKey(Product, on_delete=models.CASCADE, related_name='productimages', blank=True)
    image = models.ImageField(upload_to='product_images', null=True, blank=True)

class ProductInformation(models.Model):
    product = models.ForeignKey(
        Product,
        on_delete=models.CASCADE,
        related_name='productinformations',
        blank=True,
        null=True
    )
    text = models.TextField()

    def __str__(self):
        return f"{self.product.title} -> {self.text}"
