from django.db import models

class AbstractBaseTimeControl(models.Model):
    updated_at = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        abstract = True

class AbstractBaseRelational(models.Model):
    title = models.CharField(max_length=255)

    def __str__(self):
        return self.title

    class Meta:
        abstract = True

class Category(AbstractBaseRelational):
    grand_parent = models.ForeignKey('self', on_delete=models.CASCADE, null=True, blank=True, related_name='grandparentcategory')
    parent = models.ForeignKey('self', on_delete=models.CASCADE, null=True, blank=True, related_name='parentcategory')

class Size(AbstractBaseRelational):
    pass

class Color(AbstractBaseRelational):
    pass

class Brand(AbstractBaseRelational):
    parent = models.ForeignKey('self', on_delete=models.CASCADE, null=True, blank=True, related_name='parentbrand')