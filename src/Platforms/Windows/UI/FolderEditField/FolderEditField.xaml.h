#pragma once

#include "FolderEditField.g.h"

namespace winrt::WindowsUI::implementation
{
    struct FolderEditField : FolderEditFieldT<FolderEditField>
    {
        FolderEditField()
        {
            // Xaml objects should not call InitializeComponent during construction.
            // See https://github.com/microsoft/cppwinrt/tree/master/nuget#initializecomponent
        }

        winrt::hstring Title();
        void Title(winrt::hstring value);

        winrt::hstring Value();
        void Value(winrt::hstring value);

        void AddOption(winrt::hstring value);

        winrt::Microsoft::UI::Xaml::Controls::ComboBox GetComboBox();

        bool SuppressSelectionChanged() { return m_suppressSelectionChanged; }
        void SuppressSelectionChanged(bool value) { m_suppressSelectionChanged = value; }
    private:
        winrt::event<Microsoft::UI::Xaml::RoutedEventHandler> m_DeleteFieldEvent;
        bool m_suppressSelectionChanged = false;
    };
}

namespace winrt::WindowsUI::factory_implementation
{
    struct FolderEditField : FolderEditFieldT<FolderEditField, implementation::FolderEditField>
    {
    };
}
