# Generated migration for adding analysis_mode field

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('analyzer', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='pcapanalysis',
            name='analysis_mode',
            field=models.CharField(
                default='full',
                help_text='Modo de análise: full, llm_heuristics, llm_yara, llm_only, yara_only',
                max_length=20
            ),
        ),
    ]
