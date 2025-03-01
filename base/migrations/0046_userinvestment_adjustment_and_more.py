# Generated by Django 5.1.2 on 2024-11-13 13:10

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('base', '0045_investmentplan_plan_id'),
    ]

    operations = [
        migrations.AddField(
            model_name='userinvestment',
            name='adjustment',
            field=models.IntegerField(default=0),
        ),
        migrations.AlterField(
            model_name='userinvestment',
            name='investment_status',
            field=models.CharField(choices=[('awaiting', 'Awaiting'), ('active', 'Active'), ('completed', 'Completed'), ('canceled', 'Canceled')], default='awaiting', max_length=20),
        ),
    ]
